# -*- coding: utf-8 -*-

# Helm
# widgets/memswap.py

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

from re import findall

from helm.models.mem import Mem, Swap
from helm import widget


class MemSwap(widget.Widget):
    def __init__(self, view_class, view_args={}):
        widget.Widget.__init__(self)
        self.views.append(view_class(Mem(), **view_args))

        meminfo = open('/proc/meminfo', 'r').read()
        if int(findall('SwapTotal:\s*(\d+) kB', meminfo)[0]):
            self.views.append(view_class(Swap(), **view_args))

        for view in self.views:
            self.pack_start(view)
