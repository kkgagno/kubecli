# -*- coding: utf-8 -*-

# Helm
# models/fs.py

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

import os

from helm import model


class FS(model.Model):
    def __init__(self, path, name=None):
        model.Model.__init__(self)
        self.path = path
        self.name = path if name is None else name
        self.free = 0.
        self.total = 1.
        if not os.path.exists(self.path):
            self.valid = False
            print 'error: [FS] path "%s" does not exist.' % self.path

    @property
    def value(self):
        if self.free >= 2 ** 40:
            return '%dTiB' % (self.free / 2 ** 40)
        if self.free >= 2 ** 30:
            return '%dGiB' % (self.free / 2 ** 30)
        if self.free >= 2 ** 20:
            return '%dMiB' % (self.free / 2 ** 20)
        if self.free >= 2 ** 10:
            return '%dKiB' % (self.free / 2 ** 10)
        return '%dB' % self.free

    def update(self):
        self.update_infos()
        self.pct = 1. - float(self.free) / self.total

    def update_infos(self):
        stat = os.statvfs(self.path)
        self.free = stat.f_bavail * stat.f_bsize
        self.total = stat.f_blocks * stat.f_frsize
