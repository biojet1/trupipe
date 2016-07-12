<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:strip-space elements="*" />
	<xsl:output method="xml" encoding="ascii" indent="no"/>
	<xsl:template match="/ | @* | node()">
		<xsl:copy>
		  <xsl:apply-templates select="@* | node()"/>
		</xsl:copy>
	</xsl:template>
	<xsl:template match="title">
		<xsl:copy>
			<xsl:attribute name="property">name</xsl:attribute>
			<xsl:apply-templates select="@* | node()"/>
		</xsl:copy>
	</xsl:template>
	<xsl:template match="body">
		<xsl:copy>
			<xsl:attribute name="property">content</xsl:attribute>
			<xsl:apply-templates select="@* | node()"/>
		</xsl:copy>
	</xsl:template>
	<xsl:template match="html">
		<xsl:copy>
			<xsl:attribute name="vocab">http://schema.org</xsl:attribute>
			<xsl:attribute name="typeof">post</xsl:attribute>
			<xsl:attribute name="about">.</xsl:attribute>
			<xsl:apply-templates select="@* | node()"/>
		</xsl:copy>
	</xsl:template>
	<xsl:template match="head">
		<xsl:copy>
			<xsl:apply-templates select="@* | node()"/>
			<meta property="slug" content="cdsize-pl"/>
			<meta property="term" content="Project"/>
			<meta property="term" content="Perl"/>
			<meta property="datePublished" content="2013-01-14 00:00:00+0800"/>
		</xsl:copy>
	</xsl:template>
</xsl:stylesheet>
