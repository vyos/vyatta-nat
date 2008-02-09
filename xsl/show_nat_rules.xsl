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
      * Module: show_nat_rules.xsl  
      *
      * Author: Mike Horn
      * Date: 2006
      *
      */ -->

<!--XSL Template for formatting the "show nat rules" command-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:include href="url-decode.xsl" />

<xsl:variable name="pad6" select="'      '"/>
<xsl:variable name="pad6_len" select="string-length($pad6)"/>
<xsl:variable name="pad7" select="'       '"/>
<xsl:variable name="pad7_len" select="string-length($pad7)"/>
<xsl:variable name="pad11" select="'           '"/>
<xsl:variable name="pad11_len" select="string-length($pad11)"/>
<xsl:variable name="pad13" select="'             '"/>
<xsl:variable name="pad13_len" select="string-length($pad13)"/>
<xsl:variable name="pad20" select="'                    '"/>
<xsl:variable name="pad20_len" select="string-length($pad20)"/>


<xsl:template match="opcommand">
<xsl:text>&newln;</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>Type Codes:  SRC - source, DST - destination, MASQ - masquerade&newln;</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>rule  type     IN         OUT     source              destination         translation</xsl:text>
<xsl:text>&newln;</xsl:text>
<xsl:text>----  ----  ---------  ---------  ------              -----------         -----------</xsl:text>
<xsl:text>&newln;</xsl:text>

<xsl:for-each select="format/row">

<xsl:value-of select="rule_num"/>
<xsl:value-of select="substring($pad6,1,$pad6_len - string-length(rule_num))"/>
  
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
      <xsl:value-of select="substring($pad11,1,$pad11_len - string-length(out_interface))"/>
    </xsl:when>
  </xsl:choose>

  <xsl:choose>
    <xsl:when test="src_addr=''">
      <xsl:value-of select="src_network"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(src_network))"/>
    </xsl:when>

    <xsl:when test="src_addr!='0.0.0.0'">
      <xsl:value-of select="src_addr"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(src_addr))"/>
    </xsl:when>

    <xsl:when test="src_addr='0.0.0.0'">
      <xsl:value-of select="src_network"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(src_network))"/>
    </xsl:when>
  </xsl:choose>

  <xsl:choose>
    <xsl:when test="dst_addr=''">
      <xsl:value-of select="dst_network"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(dst_network))"/>
    </xsl:when>

    <xsl:when test="dst_addr!='0.0.0.0'">
      <xsl:value-of select="dst_addr"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(dst_addr))"/>
    </xsl:when>

    <xsl:when test="dst_addr='0.0.0.0'">
      <xsl:value-of select="dst_network"/>
      <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(dst_network))"/>
    </xsl:when>
  </xsl:choose>

  <xsl:if test="type='destination'">
    <xsl:choose>
      <xsl:when test="in_addr=''">
        <xsl:value-of select="in_network"/>
        <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(in_network))"/>
      </xsl:when>

      <xsl:when test="in_addr!='0.0.0.0'">
        <xsl:value-of select="in_addr"/>
        <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(in_addr))"/>
      </xsl:when>

      <xsl:when test="in_addr='0.0.0.0'">
        <xsl:value-of select="in_network"/>
        <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(in_network))"/>
     </xsl:when>
    </xsl:choose>
  </xsl:if>

  <xsl:if test="type!='destination'">
    <xsl:choose>
      <xsl:when test="out_addr=''">
        <xsl:value-of select="out_network"/>
        <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(out_network))"/>
      </xsl:when>

      <xsl:when test="out_addr!='0.0.0.0'">
        <xsl:value-of select="out_addr"/>
        <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(out_addr))"/>
      </xsl:when>

      <xsl:when test="out_addr='0.0.0.0'">
        <xsl:value-of select="out_network"/>
        <xsl:value-of select="substring($pad20,1,$pad20_len - string-length(out_network))"/>
     </xsl:when>
    </xsl:choose>
  </xsl:if>

  <xsl:text>&newln;</xsl:text>

  <xsl:if test="src_ports!=''">
    <xsl:variable name="src_ports_d">
      <xsl:call-template name="decode">
        <xsl:with-param name="encoded" select="src_ports"/>
      </xsl:call-template>
    </xsl:variable>

    <xsl:value-of select="$pad6"/>
    <xsl:value-of select="$pad6"/>
    <xsl:value-of select="$pad11"/>
    <xsl:value-of select="$pad11"/>

    <xsl:choose>
      <xsl:when test="$src_ports_d!=''">
        <xsl:text>src ports: </xsl:text>
        <xsl:value-of select="$src_ports_d"/>
      </xsl:when> 
    </xsl:choose>
    <xsl:text>&newln;</xsl:text>
  </xsl:if>

  <xsl:if test="dst_ports!=''">
    <xsl:variable name="dst_ports_d">
      <xsl:call-template name="decode">
        <xsl:with-param name="encoded" select="dst_ports"/>
      </xsl:call-template>
    </xsl:variable>

    <xsl:value-of select="$pad6"/>
    <xsl:value-of select="$pad6"/>
    <xsl:value-of select="$pad11"/>
    <xsl:value-of select="$pad11"/>
    <xsl:value-of select="$pad20"/>

    <xsl:choose>
      <xsl:when test="$dst_ports_d!=''">
        <xsl:text>dst ports: </xsl:text>
        <xsl:value-of select="$dst_ports_d"/>
      </xsl:when> 
    </xsl:choose>
    <xsl:text>&newln;</xsl:text>
  </xsl:if>

</xsl:for-each>
</xsl:template>

</xsl:stylesheet>

