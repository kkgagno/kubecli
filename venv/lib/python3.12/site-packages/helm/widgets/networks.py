# -*- coding: utf-8 -*-

# Helm
# widgets/networks.py

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

from helm.models.network import Network
from helm import widget


class Networks(widget.Widget):
    def __init__(self, view_class, forced_interfaces=None,
                 view_args={}):
        widget.Widget.__init__(self)

        net_route_file = open('/proc/net/route', 'r')
        net_route = net_route_file.read().split('\n')[1:-1]
        net_route_file.close()

        interfaces = set([line.split()[0] for line in net_route])
        if forced_interfaces:
            for interface in forced_interfaces:
                interfaces.add(interface)
        else:
            forced_interfaces = dict()
        interfaces = list(interfaces)
        interfaces.sort()

        for interface in interfaces:
            bp_max = forced_interfaces.get(interface)
            if bp_max:
                model = Network(interface, bp_max=bp_max)
            else:
                model = Network(interface)
            view = view_class(model, **view_args)
            self.views.append(view)
            self.pack_start(view)
