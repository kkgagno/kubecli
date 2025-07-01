# -*- coding: utf-8 -*-

# Helm
# models/cpu.py

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

from helm import model


class CPU(model.Model):
    def __init__(self, core=None):
        model.Model.__init__(self)
        self.core = core
        self.name = 'CPU' + (str(self.core) if self.core is not None else '')
        self.last = self.get_values()

    def update(self):
        user_time, total_time = self.get_values()
        if total_time == self.last[1]:
            return
        self.pct = float(user_time - self.last[0]) / (total_time - self.last[1])
        self.last = user_time, total_time

    def get_values(self):
        stat_file = open('/proc/stat', 'r')
        stat = stat_file.read().split('\n')
        stat_file.close()
        if self.core is None:
            cpu = stat[0]
        else:
            cpu = stat[self.core + 1]
            if not cpu.startswith(self.name.lower()):
                return 0, 0
        cpu = cpu[5:]

        times = [int(x) for x in cpu.split(' ')]
        total_time = sum(times)
        return times[0], total_time
