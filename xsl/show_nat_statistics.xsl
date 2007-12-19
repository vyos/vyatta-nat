<?xml version="1.0"?>
<!DOCTYPE stylesheet [
<!ENTITY newln "&#10;">
]>

<!-- /*
      *  Copyright 2006, Vyatta, Inc.
      *
      *  GNU General Public License
      *
      *  This program is free software; you can redistribute it and/or modify
      *  it under the terms of the GNU General Public License, version 2,
      *  as published by the Free Software Foundation.
      *
      *  This program is distributed in the hope that it will be useful,
      *  but WITHOUT ANY WARRANTY; without even the implied warranty of
      *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      *  GNU General Public License for more details.
      *
      *  You should have received a copy of the GNU General Public License
      *  along with this program; if not, write to the Free Software
      *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
      *  02110-1301 USA
      *
      * Module: show_nat_statistics.xsl  
      *
      * Author: Mike Horn
      * Date: 2006
      *
      */ -->

<!--XSL Template for formatting the "show nat statistics" command-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:variable name="pad6" select="'      '"/>
<xsl:variable name="pad6_len" select="string-length($pad6)"/>
<xsl:variable name="pad10" select="'          '"/>
<xsl:variable name="pad10_len" select="string-length($pad10)"/>
<xsl:variable name="pad11" select="'           '"/>
<xsl:variable name="pad11_len" select="string-length($pad11)"/>
<xsl:variable name="pad12" select="'            '"/>
<xsl:variable name="pad12_len" select="string-length($pad12)"/>

<xsl:template match="opcommand">

<xsl:text>&newln;</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>Type Codes:  SRC - source, DST - destination, MASQ - masquerade&newln;</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>rule  packets   bytes     type     IN         OUT</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>----  -------   -----     ----  ---------  ---------</xsl:text>
<xsl:text>&newln;</xsl:text>

<xsl:for-each select="format/row">

<xsl:value-of select="rule_num"/>
<xsl:value-of select="substring($pad6,1,$pad6_len - string-length(rule_num))"/>
  
<xsl:value-of select="pkts"/>
<xsl:value-of select="substring($pad10,1,$pad10_len - string-length(pkts))"/>

<xsl:value-of select="bytes"/>
<xsl:value-of select="substring($pad10,1,$pad10_len - string-length(bytes))"/>

  <xsl:choose>
    <xsl:when test="type='source'">
      <xsl:text>SRC   </xsl:text>
    </xsl:when>

    <xsl:when test="type='destination'">
      <xsl:text>DST   </xsl:text>
    </xsl:when>

    <xsl:when test="type='masquerade'">
      <xsl:text>MASQ  </xsl:text>
    </xsl:when>
  </xsl:choose>

  <xsl:choose>
    <xsl:when test="in_interface=''">
      <xsl:text>    -      </xsl:text>
    </xsl:when>

    <xsl:when test="in_interface!=''">
      <xsl:value-of select="in_interface"/>
      <xsl:value-of select="substring($pad11,1,$pad11_len - string-length(in_interface))"/>
    </xsl:when>
  </xsl:choose>

  <xsl:choose>
    <xsl:when test="out_interface=''">
      <xsl:text>    -      </xsl:text>
    </xsl:when>

    <xsl:when test="out_interface!=''">
      <xsl:value-of select="out_interface"/>
    </xsl:when>
  </xsl:choose>

<xsl:text>&newln;</xsl:text>
  
</xsl:for-each>
</xsl:template>

</xsl:stylesheet>
