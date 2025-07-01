# -*- coding: utf-8 -*-

# Helm
# theme.py

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

from color import Color, BLACK, GREEN, WHITE, GREY56, PINKG7


class Element(object):
    def __init__(self, theme=None, name=None):
        self.__dict__['_theme'] = theme
        self.__dict__['_name'] = name
        self.__dict__['fg_color'] = None
        self.__dict__['bg_color'] = None

    def __getattribute__(self, name):
        __dict__ = object.__getattribute__(self, '__dict__')
        if name == '__dict__':
            return __dict__

        if __dict__[name] is None:
            if __dict__['_theme'] is None:
                return None
            return getattr(getattr(__dict__['_theme'],
                                   __dict__['_name']),
                           name)

        return self.__dict__[name]

    def __setattr__(self, name, value):
        if not isinstance(value, Color):
            value = Color(value)
        self.__dict__[name] = value

    def __delattr__(self, *_):
        pass


class View(object):
    def __init__(self, theme):
        for name in ('text', 'drawing', 'drawing2'):
            self.__dict__[name] = Element(theme, name)

    def __setattr__(self, *_):
        pass

    def __delattr__(self, *_):
        pass


class Theme(object):
    def __init__(self):
        for name in ('text', 'drawing', 'drawing2'):
            self.__dict__[name] = Element()
        self.__dict__['_views'] = dict()

        self.text.fg_color = GREEN
        self.text.bg_color = BLACK
        self.drawing.fg_color = WHITE
        self.drawing.bg_color = GREY56
        self.drawing2.fg_color = BLACK
        self.drawing2.bg_color = GREY56

        self.init()

    def init(self):
        pass

    def __getattr__(self, name):
        if name[0].isupper():
            views = self._views
            if name not in views:
                views[name] = View(self)
            return views[name]

    def __setattr__(self, *_):
        pass

    def __delattr__(self, *_):
        pass


class GruikOPiou(Theme):
    def init(self):
        self.text.fg_color = PINKG7
        self.text.bg_color = BLACK
        self.drawing.fg_color = PINKG7
        self.drawing.bg_color = Color((.5, .0, .5), .5)
        self.drawing2.fg_color = BLACK
        self.drawing2.bg_color = GREY56
