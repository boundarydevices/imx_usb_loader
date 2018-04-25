/*
 * imx_sdp_simulation:
 * A simple client side implementation of the Serial Download Protocol (SDP)
 * for testing.
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

#ifndef __IMX_SDP_SIMULATION_H__
#define __IMX_SDP_SIMULATION_H__

int do_simulation(struct sdp_dev *dev, int report, unsigned char *p, unsigned int cnt,
		unsigned int expected, int* last_trans);
void do_simulation_cleanup(void);

#endif /* __IMX_SDP_SIMULATION_H__ */
