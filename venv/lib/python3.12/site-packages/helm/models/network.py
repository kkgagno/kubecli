# -*- coding: utf-8 -*-

# Helm
# models/network.py

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
import re

from helm import model


class Network(model.Model):
    re_bytes = '\s*%s:\s*(\d+)(?:\s*\d+){7}\s*(\d+).*'

    def __init__(self, interface, name=None, bp_max=(2 * 1024 * 1024)):
        model.Model.__init__(self)
        self.interface = interface
        self.name = interface if name is None else name
        self.bp_max = float(bp_max)
        self.re_bytes = re.compile(Network.re_bytes % self.interface)
        self.rx, self.tx = self.get_values()

    @property
    def value(self):
        speed = self.pct * self.bp_max

        if speed >= 2 ** 40:
            return '%dTi' % (speed / 2 ** 40)
        if speed >= 2 ** 30:
            return '%dGi' % (speed / 2 ** 30)
        if speed >= 2 ** 20:
            return '%dMi' % (speed / 2 ** 20)
        if speed >= 2 ** 10:
            return '%dKi' % (speed / 2 ** 10)
        return '%d' % speed

    def update(self):
        rx, tx = self.get_values()
        self.pct = ((rx + tx) - (self.rx + self.tx)) / self.bp_max
        self.rx, self.tx = rx, tx

    def get_values(self):
        net_dev_file = open('/proc/net/dev', 'r')
        net_dev = net_dev_file.read().split('\n')
        net_dev_file.close()

        for line in net_dev:
            if self.interface in line:
                break
        else:
            return 0, 0
        return [int(x) for x in self.re_bytes.findall(line)[0]]
