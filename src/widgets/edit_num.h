/**
 * File:   edit_num.h
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

#ifndef TK_EDIT_NUM_H
#define TK_EDIT_NUM_H

#include "base/widget.h"

BEGIN_C_DECLS
/**
 * @class edit_num_t
 * @parent widget_t
 * @annotation ["scriptable","design","widget"]
 * a widget that input number by using direction buttons
 */
typedef struct _edit_num_t {
  widget_t widget;

  /**
   * @property {bool_t} fixed_length
   * @annotation ["set_prop","get_prop","readable","persitent","design","scriptable"]
   * 数字是固定长度的，不可删除或者增加数字的位数。。
   */
  bool_t fixed_length;

  /**
   * @property {int32_t} max_length
   * @annotation ["set_prop","get_prop","readable","persitent","design","scriptable"]
   * 可编辑数字的最大长度。。
   */
  int32_t max_length;

  /**
   * @property {bool_t} hex
   * @annotation ["set_prop","get_prop","readable","persitent","design","scriptable"]
   * 数字是十六进制。。
   */
  bool_t hex;

  /**
   * @property {bool_t} hex_lower
   * @annotation ["set_prop","get_prop","readable","persitent","design","scriptable"]
   * 小写显示十六进制。
   */
  bool_t hex_lower;

  /* private */
  int cursor;
  str_t value;

} edit_num_t;

/**
 * @method edit_num_create
 * @annotation ["constructor", "scriptable"]
 * 创建edit_num对象
 * @param {widget_t*} parent 父控件
 * @param {xy_t} x x坐标
 * @param {xy_t} y y坐标
 * @param {wh_t} w 宽度
 * @param {wh_t} h 高度
 *
 * @return {widget_t*} 对象。
 */
widget_t* edit_num_create(widget_t* parent, xy_t x, xy_t y, wh_t w, wh_t h);

/**
 * @method edit_num_cast
 * 转换为edit_num对象(供脚本语言使用)。
 * @annotation ["cast", "scriptable"]
 * @param {widget_t*} widget edit_num对象。
 *
 * @return {widget_t*} edit_num对象。
 */
widget_t* edit_num_cast(widget_t* widget);

/**
 * @method edit_num_set_fixed_length
 * 设置fixed_length。
 * @annotation ["scriptable"]
 * @param {widget_t*} widget widget对象。
 * @param {uint32_t} fixed_length 数字是固定长度的，不可删除或者增加数字的位数。。
 *
 * @return {ret_t} 返回RET_OK表示成功，否则表示失败。
 */
ret_t edit_num_set_fixed_length(widget_t* widget, bool_t fixed_length);

/**
 * @method edit_num_set_max_length
 * 设置max_length。
 * @annotation ["scriptable"]
 * @param {widget_t*} widget widget对象。
 * @param {uint32_t} max_length 可编辑数字的最大长度。。
 *
 * @return {ret_t} 返回RET_OK表示成功，否则表示失败。
 */
ret_t edit_num_set_max_length(widget_t* widget, int32_t max_length);

/**
 * @method edit_num_set_hex
 * 设置hex。
 * @annotation ["scriptable"]
 * @param {widget_t*} widget widget对象。
 * @param {uint32_t} hex 数字是十六进制。。
 *
 * @return {ret_t} 返回RET_OK表示成功，否则表示失败。
 */
ret_t edit_num_set_hex(widget_t* widget, bool_t hex);

/**
 * @method edit_num_set_hex_lower
 * 设置hex_lower。
 * @annotation ["scriptable"]
 * @param {widget_t*} widget widget对象。
 * @param {uint32_t} hex_lower 用小写显示十六进制数字。
 *
 * @return {ret_t} 返回RET_OK表示成功，否则表示失败。
 */
ret_t edit_num_set_hex_lower(widget_t* widget, bool_t hex_lower);

#define EDIT_NUM_PROP_FIXED_LENGTH "fixed_length"
#define EDIT_NUM_PROP_MAX_LENGTH "max_length"
#define EDIT_NUM_PROP_HEX "hex"
#define EDIT_NUM_PROP_HEX_LOWER "hex_lower"

#define WIDGET_TYPE_EDIT_NUM "edit_num"

#define EDIT_NUM(widget) ((edit_num_t*)(edit_num_cast(WIDGET(widget))))

ret_t edit_num_register(void);

/*public for subclass and runtime type check*/
TK_EXTERN_VTABLE(edit_num);

END_C_DECLS

#endif /*TK_EDIT_NUM_H*/