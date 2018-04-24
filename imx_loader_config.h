/*
 * imx_loader_config:
 * Configuration file parser for imx_usb/imx_uart loader
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __IMX_LOADER_CONFIG_H__
#define __IMX_LOADER_CONFIG_H__

struct sdp_work;

int get_val(const char** pp, int base);
const char *move_string(char *dest, const char *src, unsigned cnt);

char const *get_global_conf_path(void);
char const *get_base_path(char const *argv0);
char const *conf_file_name(char const *file, char const *base_path, char const *conf_path);
struct sdp_dev *parse_conf(const char *filename);
struct sdp_work *parse_cmd_args(int argc, char * const *argv);

#endif /* __IMX_LOADER_CONFIG_H__ */
