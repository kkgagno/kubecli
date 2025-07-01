# -*- coding: utf-8 -*-

# Helm
# color.py

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


class Color(list):
    def __new__(cls, rgb, *args, **kwds):
        if isinstance(rgb, Color):
            return rgb
        return list.__new__(cls)

    def __init__(self, rgb, alpha=1):
        list.__init__(self)
        if isinstance(rgb, basestring):
            rgb = int(rgb, 16)
        if isinstance(rgb, int):
            r = (rgb / 0x10000) % 0x100
            g = (rgb / 0x100) % 0x100
            b = rgb % 0x100
            rgb = (r, g, b)

        if all(map(lambda value: isinstance(value, int), rgb)):
            rgb = tuple(value / 255. for value in rgb)

        list.__init__(self, rgb + (alpha,))


BLACK = Color(0x0)
WHITE = Color(0xffffff)
GREY56 = Color(0x565656)

RED = Color(0xff0000)
GREEN = Color(0x00ff00)
BLUE = Color(0x0000ff)
YELLOW = Color(0xffff00)
MAGENTA = Color(0xff00ff)
CYAN = Color(0x00ffff)

PINKG7 = Color((1., 0.3, 1.))
