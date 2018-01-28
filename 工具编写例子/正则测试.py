#!/usr/bin/python
# -*- coding: utf-8 -*-
import re

#pattern = re.compile(ur">([0-9a-zA-Z]{4}.*)</")
#str = r"""<acx><ScRiPt >VaZT(9773)</ScRiPt>"""
#pattern = re.compile(ur"='([0-9a-zA-Z]{4}.*)'")
str = r"()%26%25<acx><ScRiPt%20>m8dy(9325)</ScRiPt>&pattern=/lamer/"
alert = re.sub(r"([0-9a-zA-Z]{4}\([0-9]{4}\))","prompt(1)",str)
print(alert)
#print str.replace(alert,"prompt(1)")