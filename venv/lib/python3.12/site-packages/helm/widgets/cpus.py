# -*- coding: utf-8 -*-

# Helm
# widgets/cpus.py

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

from helm.models.cpu import CPU
from helm import widget


class CPUs(widget.Widget):
    def __init__(self, view_class, view_args={}):
        widget.Widget.__init__(self)
        stat = open('/proc/stat').read()
        nb_cpus = int(stat.count('cpu')) - 1
        for i in xrange(nb_cpus):
            self.views.append(view_class(CPU(i), **view_args))
        for view in self.views:
            self.pack_start(view)
