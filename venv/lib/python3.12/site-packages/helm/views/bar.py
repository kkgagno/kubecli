# -*- coding: utf-8 -*-

# Helm
# views/bar.py

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

from helm.primitives import draw_line, draw_text, NORTHEAST
from helm import view


class Bar(view.View):
    def init(self, theme, width, height=None):
        view.View.init(self, theme, width, 20)

    def update(self):
        self.model.update()

    def draw(self, cr):
        pct = self.model.pct
        draw_line(cr, 0, 3, pct * self.width, 3, 6,
                  color=self.theme_drawing_fg_color)

        draw_text(cr, 1, 6, self.model.name,
                  fg_color=self.theme_text_fg_color,
                  bg_color=self.theme_text_bg_color,
                  border=1)
        draw_text(cr, self.width - 1, 6, self.model.value,
                  fg_color=self.theme_text_fg_color,
                  bg_color=self.theme_text_bg_color,
                  border=1, reference=NORTHEAST)
