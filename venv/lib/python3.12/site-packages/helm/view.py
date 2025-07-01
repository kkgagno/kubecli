# -*- coding: utf-8 -*-

# Helm
# view.py

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

import array

import cairo
import gtk
from PIL import Image
from Xlib.X import ZPixmap

from helm.theme import Theme


# from /usr/include/X11/Xlib.h
AllPlanes = 2 ** 32 - 1


class View(gtk.DrawingArea):
    __gsignals__ = {'expose-event': 'override'}
    pix = None

    def __init__(self, model, scale=None):
        gtk.DrawingArea.__init__(self)

        self.model = model
        scale = scale or (.2, .4, .5, .8)
        self.scale = (0.,) + tuple(scale) + (1.,)

        if not self.model.valid:
            return

        self.background = None
        self.width = 0
        self.height = 0

    @property
    def valid(self):
        return self.model.valid

    def init(self, theme, width, height=None):
        class_name = self.__class__.__name__
        self.theme_text_fg_color = getattr(theme, class_name).text.fg_color
        self.theme_text_bg_color = getattr(theme, class_name).text.bg_color
        self.theme_drawing_fg_color = getattr(theme,
                                              class_name).drawing.fg_color
        self.theme_drawing_bg_color = getattr(theme,
                                              class_name).drawing.bg_color
        self.theme_drawing2_fg_color = getattr(theme,
                                               class_name).drawing2.fg_color
        self.theme_drawing2_bg_color = getattr(theme,
                                               class_name).drawing2.bg_color

        self.width = width
        if height is None:
            height = width
        self.height = height
        self.set_size_request(width, height)

    def init_background(self):
        # get some informations
        # geom = View.pix.get_geometry()
        x, y = self.window.get_origin()
        width, height = self.window.get_size()

        # x-pixmap -> array
        data = View.pix.get_image(x, y, width, height, ZPixmap, AllPlanes).data
        image = Image.fromstring('RGB', (width, height),
                                 data, 'raw', 'BGRX')
        image_string = image.tostring()
        image_array = array.array('c', chr(0) * (len(image_string) * 4 / 3))
        for i, c in enumerate(image_string):
            image_array[(2 - (i % 3)) + 4 * (i / 3)] = c

        # array -> cairo.ImageSurface
        img_surf = cairo.ImageSurface.create_for_data(image_array,
                                                      cairo.FORMAT_RGB24,
                                                      width, height)
        self.background = img_surf

    def do_expose_event(self, *args, **kwds):
        self.redraw()

    def redraw(self):
        width, height = self.window.get_size()
        pixmap = gtk.gdk.Pixmap(self.window, width, height)
        cr = pixmap.cairo_create()
        self.draw_background(cr)
        self.draw(cr)

        gc = self.window.new_gc()
        self.window.draw_drawable(gc, pixmap, 0, 0, 0, 0, width, height)

    def draw_background(self, cr):
        if self.background is None:
            self.init_background()
        width, height = self.window.get_size()
        cr.set_source_surface(self.background)
        cr.rectangle(0, 0, width, height)
        cr.fill()

    def draw(self, cr):
        raise NotImplementedError
