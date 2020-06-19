/**
 * File:   edit_num.c
 * Author: AWTK Develop Team
 * Brief:  a widget that input number by using direction buttons
 *
 * Copyright (c) 2019 - 2019 Guangzhou ZHIYUAN Electronics Co.,Ltd.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * License file for more details.
 *
 */

/**
 * History:
 * ================================================================
 * 2019-11-14 qianfan Zhao <qianfanguijin@163.com> created
 *
 */

#include "tkc/mem.h"
#include "tkc/str.h"
#include "tkc/utils.h"
#include "edit_num.h"

static bool_t edit_num_is_in_edit_mode(edit_num_t* edit_num) {
  return edit_num->cursor >= 0;
}

static ret_t edit_num_enter_edit_mode(edit_num_t* edit_num) {
  return_value_if_fail(edit_num != NULL, RET_BAD_PARAMS);
  return_value_if_fail(edit_num->cursor < 0, RET_FAIL);

  widget_set_state(WIDGET(edit_num), WIDGET_STATE_PRESSED);
  widget_dispatch_simple_event(WIDGET(edit_num), EVT_USER_START + 1);
  edit_num->cursor = 0;

  return RET_OK;
}

static ret_t edit_num_exit_edit_mode(edit_num_t* edit_num) {
  return_value_if_fail(edit_num != NULL, RET_BAD_PARAMS);
  return_value_if_fail(edit_num->cursor >= 0, RET_FAIL);

  widget_set_state(WIDGET(edit_num), WIDGET_STATE_FOCUSED);
  widget_dispatch_simple_event(WIDGET(edit_num), EVT_USER_START + 2);
  edit_num->cursor = -1;

  return RET_OK;
}

ret_t edit_num_set_fixed_length(widget_t* widget, bool_t fixed_length) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(edit_num != NULL, RET_BAD_PARAMS);

  edit_num->fixed_length = fixed_length;

  return RET_OK;
}

ret_t edit_num_set_max_length(widget_t* widget, int32_t max_length) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(edit_num != NULL, RET_BAD_PARAMS);

  edit_num->max_length = max_length;

  return RET_OK;
}

ret_t edit_num_set_hex(widget_t* widget, bool_t hex) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(edit_num != NULL, RET_BAD_PARAMS);

  edit_num->hex = hex;

  return RET_OK;
}

ret_t edit_num_set_hex_lower(widget_t* widget, bool_t hex_lower) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(edit_num != NULL, RET_BAD_PARAMS);

  edit_num->hex_lower = hex_lower;

  return RET_OK;
}

static ret_t edit_num_check_text_value(widget_t* widget, const value_t* v) {
  const char* str = value_str(v);

  if (v->type != VALUE_TYPE_STRING) {
    return RET_FAIL;
  }

  for (; *str != '\0'; str++) {
    if (!isascii(*str)) {
      return RET_FAIL;
    }
  }

  return RET_OK;
}

static ret_t edit_num_get_prop(widget_t* widget, const char* name, value_t* v) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(edit_num != NULL && name != NULL && v != NULL, RET_BAD_PARAMS);

  if (tk_str_eq(EDIT_NUM_PROP_FIXED_LENGTH, name)) {
    value_set_bool(v, edit_num->fixed_length);
    return RET_OK;
  } else if (tk_str_eq(EDIT_NUM_PROP_MAX_LENGTH, name)) {
    value_set_int32(v, edit_num->max_length);
    return RET_OK;
  } else if (tk_str_eq(EDIT_NUM_PROP_HEX, name)) {
    value_set_bool(v, edit_num->hex);
    return RET_OK;
  } else if (tk_str_eq(EDIT_NUM_PROP_HEX_LOWER, name)) {
    value_set_bool(v, edit_num->hex_lower);
    return RET_OK;
  } else if (tk_str_eq(WIDGET_PROP_TEXT, name)) {
    value_set_str(v, edit_num->value.str);
    return RET_OK;
  }

  return RET_NOT_FOUND;
}

static ret_t edit_num_set_prop(widget_t* widget, const char* name, const value_t* v) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(widget != NULL && name != NULL && v != NULL, RET_BAD_PARAMS);

  if (tk_str_eq(EDIT_NUM_PROP_FIXED_LENGTH, name)) {
    edit_num_set_fixed_length(widget, value_bool(v));
    return RET_OK;
  } else if (tk_str_eq(EDIT_NUM_PROP_MAX_LENGTH, name)) {
    edit_num_set_max_length(widget, value_int32(v));
    return RET_OK;
  } else if (tk_str_eq(EDIT_NUM_PROP_HEX, name)) {
    edit_num_set_hex(widget, value_bool(v));
    return RET_OK;
  } else if (tk_str_eq(EDIT_NUM_PROP_HEX_LOWER, name)) {
    edit_num_set_hex_lower(widget, value_bool(v));
    return RET_OK;
  } else if (tk_str_eq(WIDGET_PROP_TEXT, name)) {
    if (edit_num_check_text_value(widget, v) == RET_OK) {
      str_from_value(&edit_num->value, v);
      return RET_OK;
    }
  }

  return RET_NOT_FOUND;
}

static ret_t edit_num_on_destroy(widget_t* widget) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(widget != NULL, RET_BAD_PARAMS);

  str_reset(&edit_num->value);

  return RET_OK;
}

static ret_t edit_num_swap_color(widget_t* widget, canvas_t* c) {
  color_t fill_color, text_color;

  (void)widget;
  return_value_if_fail(canvas_get_fill_color(c, &fill_color) == RET_OK, RET_BAD_PARAMS);
  return_value_if_fail(canvas_get_text_color(c, &text_color) == RET_OK, RET_BAD_PARAMS);
  return_value_if_fail(canvas_set_fill_color(c, text_color) == RET_OK, RET_BAD_PARAMS);
  return_value_if_fail(canvas_set_text_color(c, fill_color) == RET_OK, RET_BAD_PARAMS);

  return RET_OK;
}

static ret_t edit_num_draw_text(widget_t* widget, canvas_t* c, rect_t* cr, const wchar_t* wstr,
                                uint32_t nr, int cursor) {
  for (int i = 0; i < nr; i++) {
    float cw = canvas_measure_text(c, wstr + i, 1);
    if (cr->x + cw >= widget->w) {
      break;
    }

    if (i == cursor) {
      edit_num_swap_color(widget, c);
      canvas_fill_rect(c, cr->x, cr->y, cw, cr->h);
      canvas_draw_text_in_rect(c, wstr + i, 1, cr);
      edit_num_swap_color(widget, c);
    } else {
      canvas_draw_text_in_rect(c, wstr + i, 1, cr);
    }

    cr->x += cw;
  }

  return RET_OK;
}

static ret_t edit_num_on_paint_self(widget_t* widget, canvas_t* c) {
  rect_t cr = rect_init(0, 0, widget->w, widget->h);
  edit_num_t* edit_num = EDIT_NUM(widget);
  wstr_t wstr;

  return_value_if_fail(wstr_init(&wstr, 0) != NULL, RET_FAIL);
  return_value_if_fail(wstr_set_utf8(&wstr, edit_num->value.str) == RET_OK, RET_FAIL);
  widget_prepare_text_style(widget, c);
  edit_num_draw_text(widget, c, &cr, wstr.str, wstr.size, edit_num->cursor);
  wstr_reset(&wstr);

  return RET_OK;
}

static int char2xdigit(int c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  } else if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }

  return_value_if_fail(0, 0);
  return 0;
}

static char xdigit2char(int x) {
  if (x >= 0 && x <= 9) {
    return x + '0';
  } else if (x >= 10 && x <= 15) {
    return x - 10 + 'A';
  }

  return_value_if_fail(0, '0');
  return '0';
}

static ret_t edit_num_select_next_value(edit_num_t* edit_num, int step) {
  char* str = edit_num->value.str;

  return_value_if_fail(edit_num != NULL, RET_BAD_PARAMS);
  return_value_if_fail(edit_num->cursor >= 0, RET_FAIL);

  if (edit_num->hex == FALSE) {
    int x = str[edit_num->cursor] - '0';
    int n = (x + step + 10) % 10;

    return_value_if_fail(x >= 0 && x <= 9, RET_FAIL);
    return_value_if_fail(n >= 0 && n <= 9, RET_FAIL);

    str[edit_num->cursor] = '0' + n;
  } else {
    int x = char2xdigit(str[edit_num->cursor]);
    int c, n = (x + step + 16) % 16;

    return_value_if_fail(x >= 0 && x <= 15, RET_FAIL);
    return_value_if_fail(n >= 0 && n <= 15, RET_FAIL);

    c = xdigit2char(n);
    if (edit_num->hex_lower) {
      str[edit_num->cursor] = tolower(c);
    } else {
      str[edit_num->cursor] = toupper(c);
    }
  }

  return RET_OK;
}

static ret_t edit_num_delete_char(edit_num_t* edit_num) {
  int len = edit_num->value.size;
  return_value_if_fail(edit_num->cursor >= 0, RET_FAIL);

  if (len <= 1) { /* 不能删除最后一个字符 */
    return RET_FAIL;
  }

  str_remove(&edit_num->value, edit_num->cursor, 1);
  if (edit_num->cursor == len - 1) {
    edit_num->cursor--;
  }

  return RET_OK;
}

static ret_t edit_num_add_char(edit_num_t* edit_num) {
  int len = edit_num->value.size;

  if (len >= edit_num->max_length) { /* 无剩余空间 */
    return RET_FAIL;
  }

  str_insert(&edit_num->value, len, "0");
  edit_num->cursor++;

  return RET_OK;
}

/*
 * 支持多种可编辑的格式，例如：
 * IP:         192.168.003.025
 * float:      3.14
 * mac:        00:0e:c6:dd:d1:45
 * date:       2019-11-18
 * time:       16:59:30
 *
 * 在执行cursor_move的时候，根据edit_num->hex去跳过非可编辑的字符。如果edit_num
 * 中包含一些分隔字符，请设置edit_num->fixed_length为TRUE。
 */
static ret_t edit_num_on_cursor_move(edit_num_t* edit_num, uint32_t key) {
  str_t* v = &edit_num->value;
  int cursor = edit_num->cursor;

  if (key == TK_KEY_LEFT) {
    while (cursor >= 1) {
      char c = v->str[--cursor];
      if ((edit_num->hex && isxdigit(c)) || (!edit_num->hex && isdigit(c))) {
        break;
      }
    }
    edit_num->cursor = cursor;
  } else {
    if (cursor < v->size - 1) {
      while (cursor < v->size - 1) {
        char c = v->str[++cursor];
        if ((edit_num->hex && isxdigit(c)) || (!edit_num->hex && isdigit(c))) {
          break;
        }
      }
      edit_num->cursor = cursor;
    } else if (edit_num->fixed_length == FALSE) {
      edit_num_add_char(edit_num);
    }
  }

  return RET_OK;
}

static ret_t edit_num_on_next_value(edit_num_t* edit_num, uint32_t key) {
  int step = key == TK_KEY_UP ? 1 : -1;

  edit_num_select_next_value(edit_num, step);

  return RET_OK;
}

static ret_t edit_num_on_key_event(widget_t* widget, key_event_t* e) {
  edit_num_t* edit_num = EDIT_NUM(widget);
  int ret = RET_STOP;

  if (!edit_num_is_in_edit_mode(edit_num)) {
    /* 非编辑模式下，只响应RETURN按键，进入编辑模式 */
    if (e->key != TK_KEY_RETURN) {
      return RET_OK;
    }
  }

  switch (e->key) {
    case TK_KEY_RIGHT:
    case TK_KEY_LEFT:
      edit_num_on_cursor_move(edit_num, e->key);
      break;
    case TK_KEY_DOWN:
    case TK_KEY_UP:
      edit_num_on_next_value(edit_num, e->key);
      break;
    case TK_KEY_RETURN:
      if (edit_num_is_in_edit_mode(edit_num)) {
        edit_num_exit_edit_mode(edit_num);
      } else {
        edit_num_enter_edit_mode(edit_num);
      }
      break;
    case TK_KEY_ESCAPE:
      if (edit_num->fixed_length == FALSE) {
        edit_num_delete_char(edit_num);
      }
      break;
  }

  if (ret == RET_STOP) {
    widget_invalidate(widget, NULL);
  }

  return ret;
}

static ret_t edit_num_on_event(widget_t* widget, event_t* e) {
  int ret = RET_OK;

  return_value_if_fail(widget != NULL, RET_BAD_PARAMS);

  switch (e->type) {
    case EVT_KEY_DOWN:
      ret = edit_num_on_key_event(widget, (key_event_t*)e);
      break;
    case EVT_KEY_UP:
      ret = RET_STOP;
      break;
    case EVT_BLUR:
      edit_num_exit_edit_mode(EDIT_NUM(widget));
      widget_invalidate(widget, NULL);
      break;
    default:
      break;
  }

  return ret;
}

const char* s_edit_num_properties[] = {EDIT_NUM_PROP_FIXED_LENGTH, EDIT_NUM_PROP_MAX_LENGTH,
                                       EDIT_NUM_PROP_HEX, EDIT_NUM_PROP_HEX_LOWER, NULL};

TK_DECL_VTABLE(edit_num) = {.size = sizeof(edit_num_t),
                            .type = WIDGET_TYPE_EDIT_NUM,
                            .clone_properties = s_edit_num_properties,
                            .persistent_properties = s_edit_num_properties,
                            .parent = TK_PARENT_VTABLE(widget),
                            .create = edit_num_create,
                            .on_paint_self = edit_num_on_paint_self,
                            .set_prop = edit_num_set_prop,
                            .get_prop = edit_num_get_prop,
                            .on_event = edit_num_on_event,
                            .on_destroy = edit_num_on_destroy};

widget_t* edit_num_create(widget_t* parent, xy_t x, xy_t y, wh_t w, wh_t h) {
  widget_t* widget = widget_create(parent, TK_REF_VTABLE(edit_num), x, y, w, h);
  edit_num_t* edit_num = EDIT_NUM(widget);
  return_value_if_fail(edit_num != NULL, NULL);

  str_init(&edit_num->value, 0);
  str_from_int(&edit_num->value, 0);
  edit_num->cursor = -1;

  edit_num->fixed_length = TRUE;
  edit_num->hex = FALSE;

  return widget;
}

widget_t* edit_num_cast(widget_t* widget) {
  return_value_if_fail(WIDGET_IS_INSTANCE_OF(widget, edit_num), NULL);

  return widget;
}

#include "base/widget_factory.h"

ret_t edit_num_register(void) {
  return widget_factory_register(widget_factory(), WIDGET_TYPE_EDIT_NUM, edit_num_create);
}