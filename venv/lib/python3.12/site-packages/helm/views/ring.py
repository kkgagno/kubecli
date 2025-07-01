# -*- coding: utf-8 -*-

# Helm
# views/ring.py

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

from helm.primitives import draw_ring, draw_text, CENTER
from helm import view


class Ring(view.View):
    def __init__(self, model):
        view.View.__init__(self, model)
        self.x = 30
        self.y = 30
        self.thickness = 10
        self.r = 25

    def init(self, theme, width, height=None):
        view.View.init(self, theme, width, width)
        self.x = width / 2.
        self.y = width / 2.
        self.thickness = width / 6.
        self.r = (width - self.thickness) / 2.

    def update(self):
        self.model.update()

    def draw(self, cr):
        pct = self.model.pct
        draw_ring(cr, self.x, self.y, self.r, pct, thickness=self.thickness,
                  angle_start=-120, angle_end=120,
                  background_ring=True,
                  fg_color=self.theme_drawing_fg_color,
                  bg_color=self.theme_drawing_bg_color)

        draw_text(cr, self.x, self.y, self.model.name,
                  fg_color=self.theme_text_fg_color,
                  bg_color=self.theme_text_bg_color,
                  border=1, reference=CENTER)
