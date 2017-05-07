/*
 * Cue sheet demuxer
 * Copyright (c) 2016 The FFmpeg Project
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
 * Cue sheet demuxer
 * @author Rodger Combs <rodger.combs@gmail.com>
 */

#include "avformat.h"
#include "internal.h"
#include "subtitles.h"
#include "url.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/avstring.h"
#include "libavutil/opt.h"

typedef struct CueDemuxContext {
    AVClass *class;
    char *url;
    AVFormatContext *avf;
} CueDemuxContext;

static int cue_probe(AVProbeData *p)
{
    const unsigned char *ptr = p->buf;
    int has_file = 0, has_track = 0;

    if (AV_RB24(ptr) == 0xEFBBBF)
        ptr += 3;  /* skip UTF-8 BOM */
    while (*ptr && (!has_file || !has_track)) {
        while (*ptr == ' ' || *ptr == '\t')
            ptr++;
        if (!strncmp(ptr, "FILE ", 5)) {
            ptr += 5;
            while (*ptr == ' ' || *ptr == '\t')
                ptr++;
            if (*ptr == '"')
                has_file = 1;
        } else if (!strncmp(ptr, "TRACK ", 6)) {
            ptr += 6;
            while (*ptr == ' ' || *ptr == '\t')
                ptr++;
            if (!av_isdigit(*ptr))
                return 0;
            while (av_isdigit(*ptr))
                ptr++;
            if (*ptr != ' ' && *ptr != '\t')
                return 0;
            while (*ptr == ' ' || *ptr == '\t')
                ptr++;
            if (!strncmp(ptr, "AUDIO", 5))
                has_track = 1;
        }
        ptr += ff_subtitles_next_line(ptr);
    }
    if (has_file && has_track)
        return AVPROBE_SCORE_MAX - 5;
    return 0;
}

static char *get_token(char *in)
{
    char *end;
    while (av_isspace(*in))
        in++;
    if (*in == '"') {
        in++;
        end = in + strcspn(in, "\"\n\t\r");
    } else {
        end = in + strcspn(in, " \n\t\r");
    }
    *end = '\0';
    return in;
}

static int cue_read_header(AVFormatContext *s)
{
    int got_file = 0;
    int ret, i;
    CueDemuxContext *cue = s->priv_data;
    char line[4096], *ptr;
    AVDictionary **meta = &s->metadata;
    AVChapter *chap = NULL;
    while (ff_get_line(s->pb, line, sizeof(line))) {
        ptr = line;
        if (AV_RB24(ptr) == 0xEFBBBF)
            ptr += 3;  /* skip UTF-8 BOM */
        while (*ptr == ' ' || *ptr == '\t')
            ptr++;
        if (!strncmp(ptr, "REM ", 4)) {
            char *end = ptr + strcspn(ptr, "\r\n");
            *end = '\0';
            av_log(s, AV_LOG_INFO, "Comment: \"%s\"\n", ptr + 4);
        } else if (!strncmp(ptr, "TITLE ", 6)) {
            ptr = get_token(ptr + 6);
            av_dict_set(meta, chap ? "title" : "album", ptr, 0);
        } else if (!strncmp(ptr, "PERFORMER ", 10)) {
            ptr = get_token(ptr + 10);
            av_dict_set(meta, chap ? "artist" : "album_artist", ptr, 0);
        } else if (!strncmp(ptr, "FILE ", 5)) {
            if (got_file) {
                avpriv_request_sample(s, "Cue sheet with multiple FILE directives");
                return AVERROR_PATCHWELCOME;
            }
            if (!cue->url || !*cue->url) {
                const char *filename = get_token(ptr + 5);
                char url[4096] = {0};

                if (filename[strcspn(filename, "/\\:")] != 0) {
                    av_log(s, AV_LOG_ERROR, "Only bare filenames are allowed in cue FILE directives.\n"
                           "To read from '%s', use the 'url' option explicitly.", filename);
                    return AVERROR(EPERM);
                }

                av_freep(&cue->url);
                ff_make_absolute_url(url, sizeof(url), s->filename, filename);
                if (!(cue->url = av_strdup(url)))
                    return AVERROR(ENOMEM);
            }
            got_file = 1;
        } else if (!strncmp(ptr, "TRACK ", 6)) {
            int index = strtol(ptr + 6, &ptr, 10);
            chap = avpriv_new_chapter(s, index, (AVRational){1, 75}, AV_NOPTS_VALUE, AV_NOPTS_VALUE, NULL);
            if (!chap)
                return AVERROR(ENOMEM);
            meta = &chap->metadata;
            if ((ret = av_dict_copy(meta, s->metadata, 0)) < 0)
                return ret;
            av_dict_set_int(meta, "track", index, 0);
        } else if (!strncmp(ptr, "INDEX ", 6)) {
            int min, sec, frame;
            int index;
            if (!chap)
                return AVERROR_INVALIDDATA;
            if (sscanf(ptr + 6, "%u %u:%u:%u", &index, &min, &sec, &frame) != 4)
                return AVERROR_INVALIDDATA;
            if (index == 1 || chap->start == 0)
                chap->start = min * 75 * 60 + sec * 75 + frame;
        } else {
            av_log(s, AV_LOG_WARNING, "Unknown command: \"%s\"\n", ptr);
        }
    }

    if (!cue->url || !*cue->url)
        return AVERROR_INVALIDDATA;

    if (!(cue->avf = avformat_alloc_context()))
        return AVERROR(ENOMEM);

    cue->avf->interrupt_callback = s->interrupt_callback;
    if ((ret = ff_copy_whiteblacklists(cue->avf, s)) < 0)
        return ret;

    if ((ret = avformat_open_input(&cue->avf, cue->url, NULL, NULL)) < 0) {
        av_log(s, AV_LOG_ERROR, "Failed to open '%s'\n", cue->url);
        avformat_close_input(&cue->avf);
        return ret;
    }

    for (i = 0; i < cue->avf->nb_streams; i++) {
        AVStream *st = avformat_new_stream(s, NULL);
        AVStream *ist = cue->avf->streams[i];
        if (!st)
            return AVERROR(ENOMEM);
        st->id = i;

        avcodec_parameters_copy(st->codecpar, ist->codecpar);

        st->disposition = ist->disposition;
        avpriv_set_pts_info(st, ist->pts_wrap_bits, ist->time_base.num, ist->time_base.den);
        if ((ret = av_packet_ref(&st->attached_pic, &ist->attached_pic)) < 0)
            return ret;
    }

    s->duration = cue->avf->duration;

    return 0;
}

static int cue_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    CueDemuxContext *cue = s->priv_data;
    return av_read_frame(cue->avf, pkt);
}

static int cue_read_seek(AVFormatContext *s, int stream_index,
                         int64_t min_ts, int64_t ts, int64_t max_ts, int flags)
{
    CueDemuxContext *cue = s->priv_data;
    return avformat_seek_file(cue->avf, stream_index, min_ts, ts, max_ts, flags);
}

static int cue_read_close(AVFormatContext *s)
{
    CueDemuxContext *cue = s->priv_data;
    avformat_close_input(&cue->avf);
    return 0;
}

#define OFFSET(x) offsetof(CueDemuxContext, x)
#define E AV_OPT_FLAG_DECODING_PARAM
static const AVOption options[] = {
    { "url",  "override underlying audio location", OFFSET(url), AV_OPT_TYPE_STRING, {.str = NULL}, CHAR_MIN, CHAR_MAX, E },
    { NULL }
};

static const AVClass cue_class = {
    .class_name = "Cue sheet demuxer",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

AVInputFormat ff_cue_demuxer = {
    .name           = "cue",
    .long_name      = NULL_IF_CONFIG_SMALL("Cue sheet"),
    .extensions     = "cue",
    .priv_data_size = sizeof(CueDemuxContext),
    .read_probe     = cue_probe,
    .read_header    = cue_read_header,
    .read_packet    = cue_read_packet,
    .read_seek2     = cue_read_seek,
    .read_close     = cue_read_close,
    .priv_class     = &cue_class,
};
