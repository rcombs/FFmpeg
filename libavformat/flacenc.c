/*
 * raw FLAC muxer
 * Copyright (c) 2006-2009 Justin Ruggles
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

#include "libavutil/channel_layout.h"
#include "libavutil/opt.h"
#include "libavutil/pixdesc.h"
#include "libavcodec/flac.h"
#include "avformat.h"
#include "avio_internal.h"
#include "flacenc.h"
#include "id3v2.h"
#include "internal.h"
#include "vorbiscomment.h"
#include "libavcodec/bytestream.h"
#include "libavutil/crc.h"


typedef struct FlacMuxerContext {
    const AVClass *class;
    int write_header;

    int audio_stream_idx;
    AVPacket *pics;
    int nb_pics, waiting_pics;
    /* audio packets are queued here until we get all the attached pictures */
    AVPacketList *queue, *queue_end;

    /* updated streaminfo sent by the encoder at the end */
    uint8_t *streaminfo;

    unsigned attached_types;

    uint64_t samples;
} FlacMuxerContext;

static int flac_write_block_padding(AVIOContext *pb, unsigned int n_padding_bytes,
                                    int last_block)
{
    avio_w8(pb, last_block ? 0x81 : 0x01);
    avio_wb24(pb, n_padding_bytes);
    ffio_fill(pb, 0, n_padding_bytes);
    return 0;
}

static int flac_write_block_comment(AVIOContext *pb, AVDictionary **m,
                                    int last_block, int bitexact)
{
    const char *vendor = bitexact ? "ffmpeg" : LIBAVFORMAT_IDENT;
    int64_t len;
    uint8_t *p, *p0;

    ff_metadata_conv(m, ff_vorbiscomment_metadata_conv, NULL);

    len = ff_vorbiscomment_length(*m, vendor);
    if (len >= ((1<<24) - 4))
        return AVERROR(EINVAL);
    p0 = av_malloc(len+4);
    if (!p0)
        return AVERROR(ENOMEM);
    p = p0;

    bytestream_put_byte(&p, last_block ? 0x84 : 0x04);
    bytestream_put_be24(&p, len);
    ff_vorbiscomment_write(&p, m, vendor);

    avio_write(pb, p0, len+4);
    av_freep(&p0);
    p = NULL;

    return 0;
}

static int flac_write_picture(struct AVFormatContext *s, AVPacket *pkt)
{
    FlacMuxerContext *c = s->priv_data;
    AVIOContext *pb = s->pb;
    const AVPixFmtDescriptor *pixdesc;
    const CodecMime *mime = ff_id3v2_mime_tags;
    AVDictionaryEntry *e;
    const char *mimetype = NULL, *desc = "";
    const AVStream *st = s->streams[pkt->stream_index];
    int i, mimelen, desclen, type = 0;

    if (!pkt->data)
        return 0;

    while (mime->id != AV_CODEC_ID_NONE) {
        if (mime->id == st->codecpar->codec_id) {
            mimetype = mime->str;
            break;
        }
        mime++;
    }
    if (!mimetype) {
        av_log(s, AV_LOG_ERROR, "No mimetype is known for stream %d, cannot "
               "write an attached picture.\n", st->index);
        return AVERROR(EINVAL);
    }
    mimelen = strlen(mimetype);

    /* get the picture type */
    e = av_dict_get(st->metadata, "comment", NULL, 0);
    for (i = 0; e && i < FF_ARRAY_ELEMS(ff_id3v2_picture_types); i++) {
        if (!av_strcasecmp(e->value, ff_id3v2_picture_types[i])) {
            type = i;
            break;
        }
    }

    if ((c->attached_types & (1 << type)) & 0x6) {
        av_log(s, AV_LOG_ERROR, "Duplicate attachment for type '%s'\n", ff_id3v2_picture_types[type]);
        return AVERROR(EINVAL);
    }

    if (type == 1 && (st->codecpar->codec_id != AV_CODEC_ID_PNG ||
                      st->codecpar->width != 32 ||
                      st->codecpar->height != 32)) {
        av_log(s, AV_LOG_ERROR, "File icon attachment must be a 32x32 PNG");
        return AVERROR(EINVAL);
    }

    c->attached_types |= (1 << type);

    /* get the description */
    if ((e = av_dict_get(st->metadata, "title", NULL, 0)))
        desc = e->value;
    desclen = strlen(desc);

    avio_w8(pb, 0x06);
    avio_wb24(pb, 4 + 4 + mimelen + 4 + desclen + 4 + 4 + 4 + 4 + 4 + pkt->size);

    avio_wb32(pb, type);

    avio_wb32(pb, mimelen);
    avio_write(pb, mimetype, mimelen);

    avio_wb32(pb, desclen);
    avio_write(pb, desc, desclen);

    avio_wb32(pb, st->codecpar->width);
    avio_wb32(pb, st->codecpar->height);
    if ((pixdesc = av_pix_fmt_desc_get(st->codecpar->format)))
        avio_wb32(pb, av_get_bits_per_pixel(pixdesc));
    else
        avio_wb32(pb, 0);
    avio_wb32(pb, 0);

    avio_wb32(pb, pkt->size);
    avio_write(pb, pkt->data, pkt->size);
    return 0;
}

static int flac_finish_header(struct AVFormatContext *s)
{
    FlacMuxerContext *c = s->priv_data;
    int i, ret, padding = s->metadata_header_padding;
    if (padding < 0)
        padding = 8192;
    /* The FLAC specification states that 24 bits are used to represent the
     * size of a metadata block so we must clip this value to 2^24-1. */
    padding = av_clip_uintp2(padding, 24);

    for (i = 0; i < c->nb_pics; i++) {
        ret = flac_write_picture(s, &c->pics[i]);
        av_packet_unref(&c->pics[i]);
        if (ret)
            return ret;
    }

    ret = flac_write_block_comment(s->pb, &s->metadata, !padding,
                                   s->flags & AVFMT_FLAG_BITEXACT);
    if (ret)
        return ret;

    /* The command line flac encoder defaults to placing a seekpoint
     * every 10s.  So one might add padding to allow that later
     * but there seems to be no simple way to get the duration here.
     * So just add the amount requested by the user. */
    if (padding)
        flac_write_block_padding(s->pb, padding, 1);

    return 0;
}

static int flac_write_header(struct AVFormatContext *s)
{
    int ret, i;
    AVCodecParameters *par;
    FlacMuxerContext *c = s->priv_data;

    c->audio_stream_idx = -1;
    for (i = 0; i < s->nb_streams; i++) {
        AVStream *st = s->streams[i];
        if (st->codecpar->codec_type == AVMEDIA_TYPE_AUDIO) {
            if (c->audio_stream_idx >= 0 || st->codecpar->codec_id != AV_CODEC_ID_FLAC) {
                av_log(s, AV_LOG_ERROR, "Invalid audio stream. Exactly one FLAC "
                       "audio stream is required.\n");
                return AVERROR(EINVAL);
            }
            par = s->streams[i]->codecpar;
            c->audio_stream_idx = i;
        } else if (st->codecpar->codec_type != AVMEDIA_TYPE_VIDEO) {
            av_log(s, AV_LOG_ERROR, "Only audio streams and pictures are allowed in FLAC.\n");
            return AVERROR(EINVAL);
        } else if (st->codecpar->codec_id == AV_CODEC_ID_GIF) {
            av_log(s, AV_LOG_ERROR, "GIF image support is not implemented.\n");
            return AVERROR_PATCHWELCOME;
        } else if (!c->write_header) {
            av_log(s, AV_LOG_ERROR, "Can't write attached pictures without a header.\n");
            return AVERROR(EINVAL);
        }
    }
    if (c->audio_stream_idx < 0) {
        av_log(s, AV_LOG_ERROR, "No audio stream present.\n");
        return AVERROR(EINVAL);
    }
    c->waiting_pics = c->nb_pics = s->nb_streams - 1;
    if (c->nb_pics && !(c->pics = av_calloc(c->nb_pics, sizeof(AVPacket))))
        return AVERROR(ENOMEM);

    if (!c->write_header)
        return 0;

    ret = ff_flac_write_header(s->pb, par->extradata,
                               par->extradata_size, 0);
    if (ret)
        return ret;

    /* add the channel layout tag */
    if (par->channel_layout &&
        !(par->channel_layout & ~0x3ffffULL) &&
        !ff_flac_is_native_layout(par->channel_layout)) {
        AVDictionaryEntry *chmask = av_dict_get(s->metadata, "WAVEFORMATEXTENSIBLE_CHANNEL_MASK",
                                                NULL, 0);

        if (chmask) {
            av_log(s, AV_LOG_WARNING, "A WAVEFORMATEXTENSIBLE_CHANNEL_MASK is "
                   "already present, this muxer will not overwrite it.\n");
        } else {
            uint8_t buf[32];
            snprintf(buf, sizeof(buf), "0x%"PRIx64, par->channel_layout);
            av_dict_set(&s->metadata, "WAVEFORMATEXTENSIBLE_CHANNEL_MASK", buf, 0);
        }
    }

    if (!c->waiting_pics)
        ret = flac_finish_header(s);

    return ret;
}

static const int32_t blocksize_table[16] = {
     0,    192, 576<<0, 576<<1, 576<<2, 576<<3,      0,      0,
256<<0, 256<<1, 256<<2, 256<<3, 256<<4, 256<<5, 256<<6, 256<<7
};

static int flac_write_audio_packet(struct AVFormatContext *s, AVPacket *pkt)
{
    FlacMuxerContext *c = s->priv_data;
    uint8_t *streaminfo;
    int streaminfo_size;
    char header[16];

    /* check for updated streaminfo */
    streaminfo = av_packet_get_side_data(pkt, AV_PKT_DATA_NEW_EXTRADATA,
                                         &streaminfo_size);
    if (streaminfo && streaminfo_size == FLAC_STREAMINFO_SIZE) {
        av_freep(&c->streaminfo);

        c->streaminfo = av_malloc(FLAC_STREAMINFO_SIZE);
        if (!c->streaminfo)
            return AVERROR(ENOMEM);
        memcpy(c->streaminfo, streaminfo, FLAC_STREAMINFO_SIZE);
    }

    if (pkt->size) {
        uint8_t tmp;
        uint64_t pts = c->samples;
        int offset = 5;
        int headerlen = 4;
        int bscode, bs;
        int crc;
        if (pkt->size < FLAC_MIN_FRAME_SIZE)
            return AVERROR_INVALIDDATA;
        memcpy(header, pkt->data, 4);
        if (pkt->pts == AV_NOPTS_VALUE)
            pts = 0;
        if ((pkt->data[4] & 0xC0) == 0xC0)
            offset += ff_clz((unsigned char)~pkt->data[4]) - 25;
        else if (pkt->data[4] & 0x80)
            return AVERROR_INVALIDDATA;
        if (pkt->size <= offset + 1)
            return AVERROR_INVALIDDATA;

        // Forcing use of sample counts instead of block counts to avoid bs
        // mismatch issues
        header[1] |= 1;

        bscode = (unsigned char)header[2] >> 4;
        bs = blocksize_table[bscode];
        if (bscode == 0)
            return AVERROR_INVALIDDATA;
        if (bscode == 6) {
            if (pkt->size <= offset + 1)
                return AVERROR_INVALIDDATA;
            bs = pkt->data[offset] + 1;
        } else if (bscode == 7) {
            if (pkt->size <= offset + 2)
                return AVERROR_INVALIDDATA;
            bs = AV_RB16(&pkt->data[offset]) + 1;
        }

        c->samples += bs;

        PUT_UTF8(pts, tmp, header[headerlen++] = tmp;)
        if (headerlen > 11)
            return AVERROR_INVALIDDATA;
        if ((bscode & 0xE) == 0x6)
            header[headerlen++] = pkt->data[offset++];
        if (pkt->size <= offset + 1)
            return AVERROR_INVALIDDATA;
        if (bscode == 0x7)
            header[headerlen++] = pkt->data[offset++];
        if (pkt->size <= offset + 1)
            return AVERROR_INVALIDDATA;
        if ((header[2] & 0xC) == 0xC) {
            header[headerlen++] = pkt->data[offset++];
            if (pkt->size <= offset + 1)
                return AVERROR_INVALIDDATA;
            if ((header[2] & 0x3) == 0x3)
                return AVERROR_INVALIDDATA;
            else if (header[2] & 0x3) {
                header[headerlen++] = pkt->data[offset++];
                if (pkt->size <= offset + 1)
                    return AVERROR_INVALIDDATA;
            }
        }
        header[headerlen] = av_crc(av_crc_get_table(AV_CRC_8_ATM), 0, header, headerlen);
        headerlen++; offset++;
        crc = av_crc(av_crc_get_table(AV_CRC_16_ANSI), 0, header, headerlen);
        if (pkt->size < offset + 3)
            return AVERROR_INVALIDDATA;
        avio_write(s->pb, header, headerlen);
        avio_write(s->pb, pkt->data + offset, pkt->size - offset - 2);
        avio_wl16(s->pb, av_crc(av_crc_get_table(AV_CRC_16_ANSI), crc, pkt->data + offset, pkt->size - offset - 2));
    }
    return 0;
}

static int flac_queue_flush(AVFormatContext *s)
{
    FlacMuxerContext *c = s->priv_data;
    AVPacketList *pktl;
    int ret = 0, write = 1;

    flac_finish_header(s);

    while ((pktl = c->queue)) {
        if (write && (ret = flac_write_audio_packet(s, &pktl->pkt)) < 0)
            write = 0;
        av_packet_unref(&pktl->pkt);
        c->queue = pktl->next;
        av_freep(&pktl);
    }
    c->queue_end = NULL;
    return ret;
}

static int flac_write_trailer(struct AVFormatContext *s)
{
    AVIOContext *pb = s->pb;
    int64_t file_size;
    FlacMuxerContext *c = s->priv_data;
    uint8_t *streaminfo = c->streaminfo ? c->streaminfo :
                                          s->streams[c->audio_stream_idx]->codecpar->extradata;
    int streaminfo_size = c->streaminfo ? FLAC_STREAMINFO_SIZE :
                                          s->streams[c->audio_stream_idx]->codecpar->extradata_size;

    if (c->waiting_pics) {
        av_log(s, AV_LOG_WARNING, "No packets were sent for some of the "
               "attached pictures.\n");
        flac_queue_flush(s);
    }

    for (i = 0; i < c->nb_pics; i++)
        av_packet_unref(&c->pics[i]);
    av_freep(&c->pics);

    if (!c->write_header || !streaminfo)
        return 0;

    if (pb->seekable & AVIO_SEEKABLE_NORMAL && (streaminfo_size == FLAC_STREAMINFO_SIZE)) {
        /* rewrite the STREAMINFO header block data */
        file_size = avio_tell(pb);
        avio_seek(pb, 8, SEEK_SET);
        avio_write(pb, streaminfo, 13);
        avio_w8(pb, (streaminfo[13] & 0xF0) | ((c->samples >> 32) & 0xF));
        avio_wb32(pb, c->samples);
        avio_write(pb, streaminfo + 18, FLAC_STREAMINFO_SIZE - 18);
        avio_seek(pb, file_size, SEEK_SET);
        avio_flush(pb);
    } else {
        av_log(s, AV_LOG_WARNING, "unable to rewrite FLAC header.\n");
    }

    av_freep(&c->streaminfo);

    return 0;
}

static int flac_write_packet(struct AVFormatContext *s, AVPacket *pkt)
{
    FlacMuxerContext *c = s->priv_data;
    if (pkt->stream_index == c->audio_stream_idx) {
        if (c->waiting_pics) {
            /* buffer audio packets until we get all the pictures */
            AVPacketList *pktl = av_mallocz(sizeof(*pktl));
            int ret;
            if (!pktl) {
                ret = AVERROR(ENOMEM);
oom:
                if (s->error_recognition & AV_EF_EXPLODE) {
                    av_free(pktl);
                    return ret;
                }
                av_log(s, AV_LOG_ERROR, "Out of memory in packet queue; skipping attached pictures\n");
                c->waiting_pics = 0;
                if ((ret = flac_queue_flush(s)) < 0)
                    return ret;
                return flac_write_audio_packet(s, pkt);
            }

            ret = av_packet_ref(&pktl->pkt, pkt);
            if (ret < 0) {
                av_freep(&pktl);
                goto oom;
            }

            if (c->queue_end)
                c->queue_end->next = pktl;
            else
                c->queue = pktl;
            c->queue_end = pktl;
        } else {
            return flac_write_audio_packet(s, pkt);
        }
    } else {
        int ret, index = pkt->stream_index;

        /* warn only once for each stream */
        if (s->streams[pkt->stream_index]->nb_frames == 1) {
            av_log(s, AV_LOG_WARNING, "Got more than one picture in stream %d,"
                   " ignoring.\n", pkt->stream_index);
        }
        if (!c->waiting_pics || s->streams[pkt->stream_index]->nb_frames >= 1)
            return 0;

        if (index > c->audio_stream_idx)
            index--;

        if ((ret = av_packet_ref(&c->pics[index], pkt)) < 0)
            return ret;
        c->waiting_pics--;

        /* flush the buffered audio packets */
        if (!c->waiting_pics &&
            (ret = flac_queue_flush(s)) < 0)
            return ret;
    }

    return 0;
}

static const AVOption flacenc_options[] = {
    { "write_header", "Write the file header", offsetof(FlacMuxerContext, write_header), AV_OPT_TYPE_BOOL, {.i64 = 1}, 0, 1, AV_OPT_FLAG_ENCODING_PARAM },
    { NULL },
};

static const AVClass flac_muxer_class = {
    .class_name = "flac muxer",
    .item_name  = av_default_item_name,
    .option     = flacenc_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

AVOutputFormat ff_flac_muxer = {
    .name              = "flac",
    .long_name         = NULL_IF_CONFIG_SMALL("raw FLAC"),
    .priv_data_size    = sizeof(FlacMuxerContext),
    .mime_type         = "audio/x-flac",
    .extensions        = "flac",
    .audio_codec       = AV_CODEC_ID_FLAC,
    .video_codec       = AV_CODEC_ID_PNG,
    .write_header      = flac_write_header,
    .write_packet      = flac_write_packet,
    .write_trailer     = flac_write_trailer,
    .flags             = AVFMT_NOTIMESTAMPS,
    .priv_class        = &flac_muxer_class,
};
