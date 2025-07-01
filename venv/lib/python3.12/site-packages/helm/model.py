# -*- coding: utf-8 -*-

# Helm
# model.py

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


class Model(object):
    def __init__(self):
        self.pct = 0.
        self.valid = True

    @property
    def value(self):
        return '%i%%' % int(self.pct * 100)

    def update(self):
        raise NotImplementedError
