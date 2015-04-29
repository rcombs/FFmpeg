/*
 * MMAL Video Encoder
 * Copyright (c) 2015 Rodger Combs
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * MMAL Video Encoder
 */

#include "avcodec.h"
#include "internal.h"
#include "libavutil/atomic.h"
#include "libavutil/avassert.h"
#include "libavutil/buffer.h"
#include "libavutil/common.h"
#include "libavutil/opt.h"
#include "libavutil/log.h"

#include <bcm_host.h>
#include <interface/mmal/mmal.h>
#include <interface/mmal/vc/mmal_vc_api.h>
#include <interface/mmal/util/mmal_util.h>
#include <interface/mmal/util/mmal_util_params.h>
#include <interface/mmal/util/mmal_default_components.h>

typedef struct FFBufferEntry {
    AVBufferRef *ref;
    void *data;
    size_t length;
    int64_t pts, dts;
    int flags;
    struct FFBufferEntry *next;
} FFBufferEntry;

// MMAL_POOL_T destroys all of its MMAL_BUFFER_HEADER_Ts. If we want correct
// refcounting for AVFrames, we can free the MMAL_POOL_T only after all AVFrames
// have been unreferenced.
typedef struct FFPoolRef {
    volatile int refcount;
    MMAL_POOL_T *pool;
} FFPoolRef;

typedef struct FFBufferRef {
    MMAL_BUFFER_HEADER_T *buffer;
    FFPoolRef *pool;
} FFBufferRef;

typedef struct MMALEncodeContext {
    AVClass *av_class;
    int extra_buffers;

    MMAL_COMPONENT_T *encoder;
    MMAL_QUEUE_T *queue_encoded_frames;
    MMAL_POOL_T *pool_in;
    FFPoolRef *pool_out;

    // Waiting input packets. Because the libavcodec API requires encoding and
    // returning packets in lockstep, it can happen that queue_encoded_frames
    // contains almost all surfaces - then the encoder input queue can quickly
    // fill up and won't accept new input either. Without consuming input, the
    // libavcodec API can't return new frames, and we have a logical deadlock.
    // This is avoided by queuing such buffers here.
    FFBufferEntry *waiting_buffers, *waiting_buffers_tail;

    int64_t frames_sent;
    volatile int frames_buffered;
    int64_t packets_output;
    int eos_received;
    int eos_sent;

    char *packet_buf;
    int packet_buf_size;

    MMAL_BUFFER_HEADER_T *next_buffer;
} MMALEncodeContext;

// Assume encoder is guaranteed to produce output after at least this many
// packets (where each packet contains 1 frame).
#define MAX_DELAYED_FRAMES 16

static void ffmmal_poolref_unref(FFPoolRef *ref)
{
    if (ref && avpriv_atomic_int_add_and_fetch(&ref->refcount, -1) == 0) {
        mmal_pool_destroy(ref->pool);
        av_free(ref);
    }
}

static void ffmmal_release_packet(void *opaque, uint8_t *data)
{
    FFBufferRef *ref = opaque;

    mmal_buffer_header_release(ref->buffer);

    av_free(ref);
}

static void ffmmal_stop_encoder(AVCodecContext *avctx)
{
    MMALEncodeContext *ctx = avctx->priv_data;
    MMAL_COMPONENT_T *encoder = ctx->encoder;
    MMAL_BUFFER_HEADER_T *buffer;

    mmal_port_disable(encoder->input[0]);
    mmal_port_disable(encoder->output[0]);
    mmal_port_disable(encoder->control);

    mmal_port_flush(encoder->input[0]);
    mmal_port_flush(encoder->output[0]);
    mmal_port_flush(encoder->control);

    while ((buffer = mmal_queue_get(ctx->queue_encoded_frames)))
        mmal_buffer_header_release(buffer);

    while (ctx->waiting_buffers) {
        FFBufferEntry *buffer = ctx->waiting_buffers;

        ctx->waiting_buffers = buffer->next;

        av_buffer_unref(&buffer->ref);
        av_free(buffer);
    }
    ctx->waiting_buffers_tail = NULL;

    ctx->packets_output = ctx->eos_received = ctx->eos_sent = ctx->frames_sent = 0;
}

static av_cold int ffmmal_close_encoder(AVCodecContext *avctx)
{
    MMALEncodeContext *ctx = avctx->priv_data;

    if (ctx->encoder)
        ffmmal_stop_encoder(avctx);

    mmal_component_destroy(ctx->encoder);
    ctx->encoder = NULL;
    mmal_queue_destroy(ctx->queue_encoded_frames);
    mmal_pool_destroy(ctx->pool_in);
    ffmmal_poolref_unref(ctx->pool_out);

    return 0;
}

static void input_callback(MMAL_PORT_T *port, MMAL_BUFFER_HEADER_T *buffer)
{
    AVCodecContext *avctx = (AVCodecContext*)port->userdata;
    MMALEncodeContext *ctx = avctx->priv_data;

    if (!buffer->cmd) {
        avpriv_atomic_int_add_and_fetch(&ctx->frames_buffered, -1);
        if (buffer->flags & MMAL_BUFFER_HEADER_FLAG_TRANSMISSION_FAILED) {
            av_log(avctx, AV_LOG_ERROR, "MMAL transmission failed on input port\n");
        }
    } else if (buffer->cmd == MMAL_EVENT_ERROR) {
        MMAL_STATUS_T status = *(uint32_t *)buffer->data;
        av_log(avctx, AV_LOG_ERROR, "MMAL error '%s' on input port\n", mmal_status_to_string(status));
    } else {
        char s[20];
        av_get_codec_tag_string(s, sizeof(s), buffer->cmd);
        av_log(avctx, AV_LOG_WARNING, "Unknown MMAL event %s on input port\n", s);
    }
    mmal_buffer_header_release(buffer);
}

static void output_callback(MMAL_PORT_T *port, MMAL_BUFFER_HEADER_T *buffer)
{
    AVCodecContext *avctx = (AVCodecContext*)port->userdata;
    MMALEncodeContext *ctx = avctx->priv_data;

    if (!buffer->cmd) {
        mmal_queue_put(ctx->queue_encoded_frames, buffer);
        return;
    } else if (buffer->cmd == MMAL_EVENT_ERROR) {
        MMAL_STATUS_T status = *(uint32_t *)buffer->data;
        av_log(avctx, AV_LOG_ERROR, "MMAL error '%s' on output port\n", mmal_status_to_string(status));
    } else {
        char s[20];
        av_get_codec_tag_string(s, sizeof(s), buffer->cmd);
        av_log(avctx, AV_LOG_WARNING, "Unknown MMAL event %s on output port\n", s);
    }
    mmal_buffer_header_release(buffer);
}

static void control_port_cb(MMAL_PORT_T *port, MMAL_BUFFER_HEADER_T *buffer)
{
    AVCodecContext *avctx = (AVCodecContext*)port->userdata;
    MMAL_STATUS_T status;

    if (buffer->cmd == MMAL_EVENT_ERROR) {
        status = *(uint32_t *)buffer->data;
        av_log(avctx, AV_LOG_ERROR, "MMAL error '%s' on control port\n", mmal_status_to_string(status));
    } else {
        char s[20];
        av_get_codec_tag_string(s, sizeof(s), buffer->cmd);
        av_log(avctx, AV_LOG_WARNING, "Unknown MMAL event %s on control port\n", s);
    }

    mmal_buffer_header_release(buffer);
}

// Feed free output buffers to the encoder.
static int ffmmal_fill_output_port(AVCodecContext *avctx)
{
    MMALEncodeContext *ctx = avctx->priv_data;
    MMAL_BUFFER_HEADER_T *buffer;
    MMAL_STATUS_T status;

    if (!ctx->pool_out)
        return AVERROR_UNKNOWN; // format change code failed with OOM previously

    while ((buffer = mmal_queue_get(ctx->pool_out->pool->queue))) {
        if ((status = mmal_port_send_buffer(ctx->encoder->output[0], buffer))) {
            mmal_buffer_header_release(buffer);
            av_log(avctx, AV_LOG_ERROR, "MMAL error '%s' when sending output buffer.\n", mmal_status_to_string(status));
            return AVERROR_UNKNOWN;
        }
    }

    return 0;
}

static MMAL_FOURCC_T ffav_csp_to_mmal_csp(enum AVColorSpace csp)
{
    switch (csp) {
    case AVCOL_SPC_BT470BG:     return MMAL_COLOR_SPACE_BT470_2_BG;
    case AVCOL_SPC_BT709:       return MMAL_COLOR_SPACE_ITUR_BT709;
    case AVCOL_SPC_FCC:         return MMAL_COLOR_SPACE_FCC;
    case AVCOL_SPC_SMPTE240M:   return MMAL_COLOR_SPACE_SMPTE240M;
    default:                    return MMAL_COLOR_SPACE_UNKNOWN;
    }
}

static int ffmal_update_format(AVCodecContext *avctx)
{
    MMALEncodeContext *ctx = avctx->priv_data;
    int ret = 0;
    MMAL_COMPONENT_T *encoder = ctx->encoder;

    ffmmal_poolref_unref(ctx->pool_out);
    if (!(ctx->pool_out = av_mallocz(sizeof(*ctx->pool_out)))) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }
    ctx->pool_out->refcount = 1;

    encoder->output[0]->buffer_size =
        FFMAX(encoder->output[0]->buffer_size_min, encoder->output[0]->buffer_size_recommended);
    encoder->output[0]->buffer_num =
        FFMAX(encoder->output[0]->buffer_num_min, encoder->output[0]->buffer_num_recommended) + 10;// ctx->extra_buffers;
    ctx->pool_out->pool = mmal_pool_create(encoder->output[0]->buffer_num,
                                           encoder->output[0]->buffer_size);
    if (!ctx->pool_out->pool) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    return 0;

fail:
    return ret < 0 ? ret : AVERROR_UNKNOWN;
}

extern VCOS_LOG_CAT_T mmal_log_category;

static av_cold int ffmmal_init_encoder(AVCodecContext *avctx)
{
    MMALEncodeContext *ctx = avctx->priv_data;
    MMAL_STATUS_T status;
    MMAL_ES_FORMAT_T *format_in;
    MMAL_ES_FORMAT_T *format_out;
    MMAL_COMPONENT_T *encoder;
    int ret = 0;
    int dummy;
    MMAL_PARAMETER_VIDEO_PROFILE_T param;
    MMAL_PARAMETER_VIDEO_NALUNITFORMAT_T param2;

    mmal_vc_get_version(&dummy, &dummy, &dummy); // Forces linker to get the VC client lib
    bcm_host_init();

    if ((status = mmal_component_create(MMAL_COMPONENT_DEFAULT_VIDEO_ENCODER, &ctx->encoder)))
        goto fail;

    mmal_log_category.level = VCOS_LOG_TRACE;

    encoder = ctx->encoder;

    format_in = encoder->input[0]->format;
    format_in->type = MMAL_ES_TYPE_VIDEO;
    if (avctx->pix_fmt == AV_PIX_FMT_MMAL || 1) {
        format_in->encoding = MMAL_ENCODING_OPAQUE;
    } else {
        format_in->encoding = MMAL_ENCODING_I420;
    }

    format_in->es->video.width = format_in->es->video.crop.width = avctx->width;
    format_in->es->video.height = format_in->es->video.crop.height = avctx->height;
    format_in->es->video.color_space = ffav_csp_to_mmal_csp(avctx->colorspace);
    format_in->es->video.par.num = avctx->sample_aspect_ratio.num;
    format_in->es->video.par.den = avctx->sample_aspect_ratio.den;
    format_in->es->video.crop.x = format_in->es->video.crop.y = 0;

    status = mmal_port_format_commit(encoder->input[0]);
    if (status) goto fail;

    format_out = encoder->output[0]->format;
    if (!format_out) goto fail;

    mmal_format_copy(format_out, format_in);

    format_out->type = MMAL_ES_TYPE_VIDEO;
    format_out->encoding = MMAL_ENCODING_H264;
    format_out->encoding_variant = (avctx->flags & AV_CODEC_FLAG_GLOBAL_HEADER) ?
                                   MMAL_ENCODING_VARIANT_H264_AVC1 :
                                   MMAL_ENCODING_VARIANT_H264_DEFAULT;
    format_out->bitrate = 3000000;

    if ((status = mmal_port_format_commit(encoder->output[0])))
        goto fail;

    encoder->input[0]->buffer_size =
        FFMAX(encoder->input[0]->buffer_size_min, encoder->input[0]->buffer_size_recommended);
    encoder->input[0]->buffer_num =
        FFMAX(encoder->input[0]->buffer_num_min, encoder->output[0]->buffer_num_recommended);
    ctx->pool_in = mmal_pool_create(encoder->input[0]->buffer_num, 0);
    if (!ctx->pool_in) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    param.hdr.id = MMAL_PARAMETER_PROFILE;
    param.hdr.size = sizeof(param);
    param.profile[0].profile = MMAL_VIDEO_PROFILE_H264_HIGH;
    param.profile[0].level = MMAL_VIDEO_LEVEL_H264_4;
    status = mmal_port_parameter_set(encoder->output[0], &param.hdr);
    if(status != MMAL_SUCCESS) goto fail;

    status = mmal_port_parameter_set_boolean(encoder->output[0], MMAL_PARAMETER_VIDEO_ENCODE_INLINE_HEADER,
                                             !!(avctx->flags & AV_CODEC_FLAG_GLOBAL_HEADER));
    if(status != MMAL_SUCCESS) goto fail;

    param2.hdr.id = MMAL_PARAMETER_NALUNITFORMAT;
    param2.hdr.size = sizeof(param2);
    param2.format = (avctx->flags & AV_CODEC_FLAG_GLOBAL_HEADER) ?
                    MMAL_VIDEO_NALUNITFORMAT_FOURBYTEINTERLEAVELENGTH :
                    MMAL_VIDEO_NALUNITFORMAT_STARTCODES;
    status = mmal_port_parameter_set(encoder->output[0], &param2.hdr);
    if(status != MMAL_SUCCESS) goto fail;

    if ((ret = ffmal_update_format(avctx)) < 0)
        goto fail;

    ctx->queue_encoded_frames = mmal_queue_create();
    if (!ctx->queue_encoded_frames)
        goto fail;

    encoder->input[0]->userdata = (void*)avctx;
    encoder->output[0]->userdata = (void*)avctx;
    encoder->control->userdata = (void*)avctx;

    if ((status = mmal_port_enable(encoder->control, control_port_cb)))
        goto fail;
    if ((status = mmal_port_enable(encoder->input[0], input_callback)))
        goto fail;
    if ((status = mmal_port_enable(encoder->output[0], output_callback)))
        goto fail;

    if ((status = mmal_component_enable(encoder)))
        goto fail;

    if ((ret = ffmmal_fill_output_port(avctx)) < 0)
        goto fail;

    if (avctx->flags & CODEC_FLAG_GLOBAL_HEADER) {
        MMAL_BUFFER_HEADER_T *buffer;
        while ((buffer = mmal_queue_wait(ctx->queue_encoded_frames)) &&
               (buffer->flags & MMAL_BUFFER_HEADER_FLAG_CONFIG)) {
            int flags = buffer->flags;
            uint8_t *new_extradata = av_realloc(avctx->extradata, avctx->extradata_size + buffer->length + FF_INPUT_BUFFER_PADDING_SIZE);

            if (!new_extradata) {
                mmal_buffer_header_release(buffer);
                ret = AVERROR(ENOMEM);
                goto fail;
            }

            avctx->extradata = new_extradata;
            memcpy(avctx->extradata + avctx->extradata_size, buffer->data + buffer->offset, buffer->length);
            avctx->extradata_size += buffer->length;
            memset(avctx->extradata + avctx->extradata_size, 0, FF_INPUT_BUFFER_PADDING_SIZE);

            mmal_buffer_header_release(buffer);

            if (flags & MMAL_BUFFER_HEADER_FLAG_FRAME_END)
                break;
        }
    }

    return 0;

fail:
    ffmmal_close_encoder(avctx);
    return ret < 0 ? ret : AVERROR_UNKNOWN;
}

// Setup packet with a new reference to buffer. The buffer must have been
// allocated from the given pool.
static int ffmmal_set_ref(AVPacket *pkt, FFPoolRef *pool,
                          MMAL_BUFFER_HEADER_T *buffer)
{
    FFBufferRef *ref = av_mallocz(sizeof(*ref));
    if (!ref)
        return AVERROR(ENOMEM);

    ref->pool = pool;
    ref->buffer = buffer;

    pkt->buf = av_buffer_create((void *)buffer->data, buffer->length,
                                ffmmal_release_packet, ref,
                                AV_BUFFER_FLAG_READONLY);
    if (!pkt->buf) {
        av_free(ref);
        return AVERROR(ENOMEM);
    }

    avpriv_atomic_int_add_and_fetch(&ref->pool->refcount, 1);
    mmal_buffer_header_acquire(buffer);

    return 0;
}

// Add frames to the waiting_buffers list. We don't queue them
// immediately, because it can happen that the encoder is temporarily blocked
// (due to us not reading/returning enough output buffers) and won't accept
// new input. (This wouldn't be an issue if MMAL input buffers always were
// complete packets - then the input buffer just would have to be big enough.)
static int ffmmal_add_frame(AVCodecContext *avctx, const AVFrame *frame)
{
    MMALEncodeContext *ctx = avctx->priv_data;
    int ret = 0;
    MMAL_BUFFER_HEADER_T *buffer;
    MMAL_STATUS_T status;

    if (ctx->next_buffer) {
        if (!frame && !ctx->eos_sent) {
            ctx->next_buffer->flags |= MMAL_BUFFER_HEADER_FLAG_EOS;
            ctx->eos_sent = 1;
        }
        if ((status = mmal_port_send_buffer(ctx->encoder->input[0], ctx->next_buffer))) {
            mmal_buffer_header_release(buffer);
            av_log(avctx, AV_LOG_ERROR, "MMAL error %s when sending input\n", mmal_status_to_string(status));
            return AVERROR_UNKNOWN;
        }
        ctx->next_buffer = NULL;
        ctx->frames_sent++;
    }

    if (frame) {
        buffer = (void*)frame->data[3];
        buffer->pts = frame->pts == AV_NOPTS_VALUE ? MMAL_TIME_UNKNOWN : frame->pts;
        buffer->flags |= MMAL_BUFFER_HEADER_FLAG_FRAME;
        mmal_buffer_header_acquire(buffer);
        ctx->next_buffer = buffer;
        avpriv_atomic_int_add_and_fetch(&ctx->frames_buffered, 1);
    }

/*    // Insert at end of the list
    if (!ctx->waiting_buffers)
        ctx->waiting_buffers = buffer;
    if (ctx->waiting_buffers_tail)
        ctx->waiting_buffers_tail->next = buffer;
    ctx->waiting_buffers_tail = buffer;*/

//done:
    return ret;
}

// Move prepared/split frames from waiting_buffers to the MMAL encoder.
static int ffmmal_fill_input_port(AVCodecContext *avctx)
{/*
    MMALEncodeContext *ctx = avctx->priv_data;

    while (ctx->waiting_buffers) {
        MMAL_BUFFER_HEADER_T *mbuffer;
        FFBufferEntry *buffer;
        MMAL_STATUS_T status;

        mbuffer = mmal_queue_get(ctx->pool_in->queue);
        if (!mbuffer)
            return 0;

        buffer = ctx->waiting_buffers;

        mmal_buffer_header_reset(mbuffer);
        mbuffer->cmd = 0;
        mbuffer->pts = buffer->pts;
        mbuffer->dts = buffer->dts;
        mbuffer->flags = buffer->flags;
        mbuffer->data = buffer->data;
        mbuffer->length = buffer->length;
        mbuffer->user_data = buffer->ref;
        mbuffer->alloc_size = ctx->encoder->input[0]->buffer_size;

        if ((status = mmal_port_send_buffer(ctx->encoder->input[0], mbuffer))) {
            mmal_buffer_header_release(mbuffer);
            av_buffer_unref(&buffer->ref);
        }

        // Remove from start of the list
        ctx->waiting_buffers = buffer->next;
        if (ctx->waiting_buffers_tail == buffer)
            ctx->waiting_buffers_tail = NULL;
//        av_free(buffer);

        if (status) {
            av_log(avctx, AV_LOG_ERROR, "MMAL error '%s' when sending input\n", mmal_status_to_string(status));
            return AVERROR_UNKNOWN;
        }
    }
*/
    return 0;
}

// Fetch a encoded buffer and place it into the frame parameter.
static int ffmmal_read_packet(AVCodecContext *avctx, const AVFrame *frame, AVPacket *pkt, int *got_pkt)
{
    MMALEncodeContext *ctx = avctx->priv_data;
    MMAL_BUFFER_HEADER_T *buffer = NULL;
    MMAL_STATUS_T status = 0;
    int ret = 0;

    if (ctx->eos_received)
        goto done;

    while (1) {
        // To ensure encoding in lockstep with a constant delay between fed packets
        // and output frames, we always wait until an output buffer is available.
        // Except during start we don't know after how many input packets the encoder
        // is going to return the first buffer, and we can't distinguish encoder
        // being busy from encoder waiting for input. So just poll at the start and
        // keep feeding new data to the buffer.
        // We are pretty sure the encoder will produce output if we sent more input
        // frames than what a h264 encoder could logically delay. This avoids too
        // excessive buffering.
        // We also wait if we sent eos, but didn't receive it yet (think of encoding
        // stream with a very low number of frames).
        if (avpriv_atomic_int_get(&ctx->frames_buffered) > MAX_DELAYED_FRAMES ||
            (!frame && ctx->eos_sent)) {
            buffer = mmal_queue_wait(ctx->queue_encoded_frames);
        } else {
            buffer = mmal_queue_get(ctx->queue_encoded_frames);
        }
        if (!buffer)
            goto done;

        ctx->eos_received |= !!(buffer->flags & MMAL_BUFFER_HEADER_FLAG_EOS);
        if (ctx->eos_received)
            goto done;

        if (buffer->cmd == MMAL_EVENT_FORMAT_CHANGED) {/*
            MMAL_COMPONENT_T *encoder = ctx->encoder;
            MMAL_EVENT_FORMAT_CHANGED_T *ev = mmal_event_format_changed_get(buffer);
            MMAL_BUFFER_HEADER_T *stale_buffer;

            av_log(avctx, AV_LOG_INFO, "Changing output format.\n");

            if ((status = mmal_port_disable(encoder->output[0])))
                goto done;

            while ((stale_buffer = mmal_queue_get(ctx->queue_encoded_frames)))
                mmal_buffer_header_release(stale_buffer);

            mmal_format_copy(encoder->output[0]->format, ev->format);

            if ((ret = ffmal_update_format(avctx)) < 0)
                goto done;

            if ((status = mmal_port_enable(encoder->output[0], output_callback)))
                goto done;

            if ((ret = ffmmal_fill_output_port(avctx)) < 0)
                goto done;

            if ((ret = ffmmal_fill_input_port(avctx)) < 0)
                goto done;
*/
            av_log(avctx, AV_LOG_WARNING, "FORMAT CHANGE\n");
            mmal_buffer_header_release(buffer);
            continue;
        } else if (buffer->cmd) {
            char s[20];
            av_get_codec_tag_string(s, sizeof(s), buffer->cmd);
            av_log(avctx, AV_LOG_WARNING, "Unknown MMAL event %s on output port\n", s);
            goto done;
        } else if (buffer->length == 0) {
            // Unused output buffer that got drained after format change.
            mmal_buffer_header_release(buffer);
            continue;
        } else if (buffer->flags & MMAL_BUFFER_HEADER_FLAG_CONFIG && avctx->flags & CODEC_FLAG_GLOBAL_HEADER) {
            av_log(avctx, AV_LOG_WARNING, "RECONFIG\n");
            uint8_t *new_extradata = av_realloc(avctx->extradata, avctx->extradata_size + buffer->length + FF_INPUT_BUFFER_PADDING_SIZE);

            if (!new_extradata)
                return AVERROR(ENOMEM);

            avctx->extradata = new_extradata;
            memcpy(avctx->extradata + avctx->extradata_size, buffer->data + buffer->offset, buffer->length);
            avctx->extradata_size += buffer->length;
            memset(avctx->extradata + avctx->extradata_size, 0, FF_INPUT_BUFFER_PADDING_SIZE);

            mmal_buffer_header_release(buffer);
            continue;
        }

        av_log(avctx, AV_LOG_DEBUG, "FLAGS: %i\n", buffer->flags);
        if (ctx->packet_buf_size || !(buffer->flags & MMAL_BUFFER_HEADER_FLAG_FRAME_END)) {
            char *new_packet_buf = av_realloc(ctx->packet_buf,
                                              ctx->packet_buf_size + buffer->length);
            if (!new_packet_buf) {
                ret = AVERROR(ENOMEM);
                goto done;
            }

            memcpy(new_packet_buf + ctx->packet_buf_size,
                   buffer->data + buffer->offset, buffer->length);

            ctx->packet_buf = new_packet_buf;

            ctx->packet_buf_size += buffer->length;
        }
        if (buffer->flags & MMAL_BUFFER_HEADER_FLAG_FRAME_END) {
            ctx->packets_output++;
            if (ctx->packet_buf_size) {
                pkt->buf = av_buffer_create(ctx->packet_buf, ctx->packet_buf_size,
                                            NULL, NULL, AV_BUFFER_FLAG_READONLY);
                if (!pkt->buf) {
                    av_free(ctx->packet_buf);
                    ctx->packet_buf = NULL;
                    ctx->packet_buf_size = 0;
                    goto done;
                }
                pkt->data = ctx->packet_buf;
                pkt->size = ctx->packet_buf_size;
                ctx->packet_buf = NULL;
                ctx->packet_buf_size = 0;
            } else {
                if (!ctx->pool_out) {
                    ret = AVERROR_UNKNOWN; // format change code failed with OOM previously
                    goto done;
                }

                if ((ret = ffmmal_set_ref(pkt, ctx->pool_out, buffer)) < 0)
                    goto done;

                pkt->size = buffer->length;
                pkt->data = buffer->data + buffer->offset;
            }

            if (buffer->pts != MMAL_TIME_UNKNOWN)
                pkt->pts = buffer->pts;

            if (buffer->dts != MMAL_TIME_UNKNOWN)
                pkt->dts = buffer->dts;

            if (buffer->flags & MMAL_BUFFER_HEADER_FLAG_KEYFRAME)
                pkt->flags |= AV_PKT_FLAG_KEY;

            *got_pkt = 1;
            break;
        } else {
            mmal_buffer_header_release(buffer);
        }
    }

done:
    if (buffer)
        mmal_buffer_header_release(buffer);
    if (status && ret >= 0)
        ret = AVERROR_UNKNOWN;
    return ret;
}

static int ffmmal_encode_frame(AVCodecContext *avctx, AVPacket *pkt,
                               const AVFrame *frame, int *got_packet)
{
    int ret = 0;

    if ((ret = ffmmal_add_frame(avctx, frame)) < 0)
        return ret;

    if ((ret = ffmmal_fill_input_port(avctx)) < 0)
        return ret;

    if ((ret = ffmmal_fill_output_port(avctx)) < 0)
        return ret;

    if ((ret = ffmmal_read_packet(avctx, frame, pkt, got_packet)) < 0)
        return ret;

    // ffmmal_read_frame() can block for a while. Since the encoder is
    // asynchronous, it's a good idea to fill the ports again.

    if ((ret = ffmmal_fill_output_port(avctx)) < 0)
        return ret;

    if ((ret = ffmmal_fill_input_port(avctx)) < 0)
        return ret;

    return ret;
}

static const AVOption options[] = {
    {NULL}
};

static const AVClass ffmmalenc_class = {
    .class_name = "mmalenc",
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

AVCodec ff_h264_mmal_encoder = {
    .name           = "h264_mmal",
    .long_name      = NULL_IF_CONFIG_SMALL("h264 (mmal)"),
    .type           = AVMEDIA_TYPE_VIDEO,
    .id             = AV_CODEC_ID_H264,
    .priv_data_size = sizeof(MMALEncodeContext),
    .init           = ffmmal_init_encoder,
    .close          = ffmmal_close_encoder,
    .encode2        = ffmmal_encode_frame,

    .priv_class     = &ffmmalenc_class,
    .capabilities   = CODEC_CAP_DELAY,
    .pix_fmts       = (const enum AVPixelFormat[]) { AV_PIX_FMT_MMAL,
                                                     AV_PIX_FMT_YUV420P,
                                                     AV_PIX_FMT_NONE},
};
