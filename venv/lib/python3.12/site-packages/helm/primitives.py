# -*- coding: utf-8 -*-

# Helm
# primitives.py

# Copyright (C) 2011 Anaël Verrier <elghinn@free.fr>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 only.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import cairo
import math

from helm.color import BLACK, WHITE


CENTER = 0
NORTH = 1
EAST = 2
SOUTH = 4
WEST = 8
NORTHEAST = NORTH | EAST
SOUTHEAST = SOUTH | EAST
NORTHWEST = NORTH | WEST
SOUTHWEST = SOUTH | WEST


def draw_pixel(cr, x, y, color=WHITE):
    cr.rectangle(x, y, 1, 1)
    cr.set_source_rgba(*color)
    cr.fill()


def draw_line(cr, x1, y1, x2, y2, thickness=1, color=WHITE,
              rounded=False):
    cr.set_source_rgba(*color)

    cr.move_to(x1, y1)
    cr.line_to(x2, y2)

    if rounded:
        line_cap = cairo.LINE_CAP_ROUND
    else:
        line_cap = cairo.LINE_CAP_BUTT
    cr.set_line_cap(line_cap)

    cr.set_line_width(thickness)
    cr.stroke()


def draw_ring(cr, xc, yc, r, pct, thickness=1,
              angle_start=0, angle_end=360, angle_delta=90,
              background_ring=False, fg_color=WHITE, bg_color=BLACK):
    angle_0 = (angle_start - angle_delta) * (2 * math.pi / 360)
    angle_f = (angle_end - angle_delta) * (2 * math.pi / 360)
    pct_arc = pct * (angle_f - angle_0)

    cr.set_line_width(thickness)

    if background_ring:
        cr.arc(xc, yc, r, angle_0, angle_f)
        cr.set_source_rgba(*bg_color)
        cr.stroke()

    cr.arc(xc, yc, r, angle_0, angle_0 + pct_arc)
    cr.set_source_rgba(*fg_color)
    cr.stroke()


def _draw_text(cr, x, y, text, color):
    cr.move_to(x, y)
    cr.set_source_rgba(*color)
    cr.show_text(text)


def draw_text(cr, x, y, text, fg_color=WHITE, bg_color=BLACK, border=0,
              shadow=False, reference=NORTHWEST):
    if not isinstance(text, basestring):
        text = unicode(text)

    fascent, fdescent, fheight, fxadvance, fyadvance = cr.font_extents()
    (xbearing, ybearing,
     width, height,
     xadvance, yadvance) = cr.text_extents(text)

    dx = -width / 2
    dy = -fheight / 2

    if reference & EAST:
        x += 2 * dx
    elif not reference & WEST:
        x += dx
    if reference & SOUTH:
        y += 2 * dy
    elif not reference & NORTH:
        y += dy

    # move from the upper-left corner of the bounding box to the reference point
    x -= xbearing
    y += fascent

    if border:
        for i in xrange(-border, border + 1):
            for j in xrange(-border, border + 1):
                _draw_text(cr, x + i, y + j, text, bg_color)
    elif shadow:
        _draw_text(cr, x + 1, y + 1, text, bg_color)

    _draw_text(cr, x, y, text, fg_color)
