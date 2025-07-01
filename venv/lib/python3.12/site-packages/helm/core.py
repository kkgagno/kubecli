# -*- coding: utf-8 -*-

# Helm
# core.py

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

import glib
import gtk
from gtk.gdk import CONTROL_MASK, keyval_name
from Xlib import display, Xatom
from Xlib.xobject.drawable import Pixmap

from helm.primitives import NORTH, EAST, SOUTH, WEST, NORTHEAST
from helm.theme import Theme
from helm.view import View


class Helm(gtk.Window):
    __gsignals__ = {'key-press-event': 'override',
                    'delete-event': 'override',
                    'configure-event': 'override'}

    def __init__(self, widgets, theme=None, width=70, gravity=NORTHEAST,
                 dx=0, dy=0):
        gtk.Window.__init__(self)
        self.widgets = widgets
        self.theme = theme or Theme()

        self.display = display.Display()
        self.screen = self.display.screen()
        self.root = self.screen.root
        self._XROOTPMAP_ID = self.display.intern_atom("_XROOTPMAP_ID")
        self.ESETROOT_PMAP_ID = self.display.intern_atom("ESETROOT_PMAP_ID")
        self._NET_WORKAREA = self.display.intern_atom("_NET_WORKAREA")
        self.xid = None

        req = self.root.get_full_property(self._NET_WORKAREA, Xatom.CARDINAL)
        self.workarea = req.value[0:4].tolist()

        self.set_decorated(False)
        self.set_has_frame(False)

        self.set_skip_taskbar_hint(True)
        self.set_skip_pager_hint(True)
        # self.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DOCK)
        self.set_keep_below(True)

        self.set_title('Helm')

        vbox = gtk.VBox()
        for widget in widgets:
            if not widget.valid:
                continue
            vbox.pack_start(widget)
            widget.init(self.theme, width)
        self.add(vbox)
        self.show_all()

        width, height = self.get_size()

        x = (self.workarea[2] - width) / 2
        y = (self.workarea[3] - height) / 2

        if gravity & EAST:
            x *= 2
        elif gravity & WEST:
            x = 0
        if gravity & SOUTH:
            y *= 2
        elif gravity & NORTH:
            y = 0


        self.move(self.workarea[0] + x + dx,
                  self.workarea[1] + y + dy)

        self.present()
        self.stick()
        self.set_resizable(False)
        self.update_pix(self.get_xid())

    def do_key_press_event(self, event):
        if (event.state & CONTROL_MASK) == CONTROL_MASK:
            if keyval_name(event.keyval) == 'q':
                gtk.main_quit()

    def do_delete_event(self, event):
        gtk.main_quit()

    def do_configure_event(self, *args, **kwds):
        self.free_backgrounds()

    def run(self):
        glib.timeout_add(1000, self.loop_cb, True)
        gtk.main()

    def loop_cb(self, *args, **kwds):
        glib.idle_add(self.loop)
        return True

    def loop(self):
        current_xid = self.get_xid()
        if self.xid != current_xid:
            self.update_pix(current_xid)

        for widget in self.widgets:
            widget.update()
        for widget in self.widgets:
            widget.redraw()

    def get_xid(self):
        req = self.root.get_full_property(self._XROOTPMAP_ID, Xatom.PIXMAP)
        if not req:
            req = self.root.get_full_property(self.ESETROOT_PMAP_ID,
                                               Xatom.PIXMAP)

        if req is None:
            return None

        return req.value[0]

    def free_backgrounds(self):
        for widget in self.widgets:
            widget.background = None

    def update_pix(self, xid):
        self.xid = xid

        # get x-pixmap
        if self.xid is None:
            geom = self.root.get_geometry()
            View.pix = self.root.create_pixmap(geom.width, geom.height,
                                               self.screen.root_depth)
        else:
            View.pix = Pixmap(self.display.display, self.xid)

        self.free_backgrounds()


def run(*args, **kwds):
    glib.set_prgname('helm')
    helm = Helm(*args, **kwds)
    helm.run()
