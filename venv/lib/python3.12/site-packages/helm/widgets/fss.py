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

from helm.models.fs import FS
from helm import widget


class FSs(widget.Widget):
    def __init__(self, view_class, view_args={}):
        widget.Widget.__init__(self)
        models = list()

        mounts = open('/proc/mounts', 'r').read().split('\n')
        mounts = [mount for mount in mounts if mount.startswith('/')]

        for mount in mounts:
            path = mount.split()[1]
            name = path.split('/')[-1]
            if not name:
                name = '/'
            if name == 'home':
                name = '~'
            models.append(FS(path, name))

        for model in models:
            self.views.append(view_class(model, **view_args))

        for view in self.views:
            self.pack_start(view)
