# -*- coding: utf-8 -*-

# Helm
# views/histogram.py

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

import cairo

from helm.primitives import draw_pixel, draw_line, draw_text, CENTER
from helm import view


class Histogram(view.View):
    def __init__(self, model, dynamic_scale=True, scale=None):
        view.View.__init__(self, model, scale)
        self.dynamic_scale = dynamic_scale
        self.values = None
        self.graph_height = 0
        self.text_height = 0

    def init(self, theme, width, height=None):
        self.graph_height = 50
        self.text_height = 15
        view.View.init(self, theme, width, self.graph_height + self.text_height)
        self.values = [(0, 0) for _ in xrange(width)]

    def get_index(self, x):
        scale = list(self.scale)
        scale[-1] += 1
        for i, v in enumerate(scale):
            if v > x:
                break
        return i - 1

    def update(self):
        self.model.update()
        self.values.pop(0)
        value = self.model.pct
        self.values.append((value, self.get_index(value)))

    def draw(self, cr):
        # write model name
        draw_text(cr, self.width / 2, self.graph_height + self.text_height / 2,
                  self.model.name,
                  fg_color=self.theme_text_fg_color,
                  bg_color=self.theme_text_bg_color,
                  border=1, reference=CENTER)

        # Horizontally flip the histogram drawing area
        m = cairo.Matrix(1, 0, 0, -1, 0, self.graph_height - 1)
        cr.transform(m)

        max_height = self.graph_height - 1
        max_value = max(self.values)[0]

        values = list()
        for value, index in self.values:
            lower_bound = self.scale[index]
            upper_bound = self.scale[index + 1]
            value = index + (value - lower_bound) / (upper_bound - lower_bound)
            values.append(value)

        nb_steps = 5
        vertical_step = (max_height - 1) / float(nb_steps)

        if self.dynamic_scale:
            for i, v in enumerate(self.scale):
                if max_value < v:
                    nb_steps = i
                    vertical_step = (max_height - 1) / float(nb_steps)
                    break

        # draw horizontal lines
        for i in xrange(0, nb_steps + 1):
            height = int(i * vertical_step) + .5
            draw_line(cr, 0, height, self.width + 1, height, 1,
                      self.theme_drawing2_bg_color)

        # draw the vertical bars
        for i, value in enumerate(values):
            draw_line(cr,
                      i + .5, 0,
                      i + .5, int(value * vertical_step), 1,
                      self.theme_drawing_fg_color)

        # redraw horizontal lines where there is a collision with a vertical bar
        for i in xrange(0, nb_steps + 1):
            y = int(i * vertical_step)
            for x, value in enumerate(values):
                height = value * vertical_step
                if height and height >= y:
                    draw_pixel(cr, x, y, self.theme_drawing2_fg_color)
