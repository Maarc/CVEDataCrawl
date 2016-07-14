package org.jboss.crawl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.jsoup.Jsoup;
import org.junit.Assert;
import org.junit.Test;

/**
 * JUnit tests for Crawly.
 * 
 * @author Marc
 */
public class CrawlyTest {

	@Test
	public void testCrawlVulDBRequest2_1() throws IOException {

		final String url = "https://vuldb.com/?id.62731";
		byte[] encoded = Files.readAllBytes(Paths.get("src/test/resources/r2_1.html"));
		String[] r = Crawly.crawlVulDBRequest2(Jsoup.parse(new String(encoded, StandardCharsets.UTF_8)), url);

		for (String string : r) {
			System.out.println("string: " + string);
		}

		Assert.assertEquals(url, r[0]);
		Assert.assertEquals("$0-$1k", r[1]);
		Assert.assertEquals("7.5 (CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P)", r[2]);
		Assert.assertEquals("6.5 (CVSS2#E:ND/RL:OF/RC:ND)", r[3]);
		Assert.assertEquals("cpe:/a:jcore:jcore:1.0", r[4]);
		Assert.assertEquals("Official fix", r[5]);
		Assert.assertEquals("Upgrade [jCore 1.0]", r[6]);
	}

	@Test
	public void testCrawlVulDBRequest2_2() throws IOException {

		final String url = "https://vuldb.com/?id.62731";
		byte[] encoded = Files.readAllBytes(Paths.get("src/test/resources/r2_2.html"));
		String[] r = Crawly.crawlVulDBRequest2(Jsoup.parse(new String(encoded, StandardCharsets.UTF_8)), url);

		for (String string : r) {
			System.out.println("string: " + string);
		}

		Assert.assertEquals(url, r[0]);
		Assert.assertEquals("$2k-$5k", r[1]);
		Assert.assertEquals("5.8 (CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N)", r[2]);
		Assert.assertEquals("5.8 (CVSS2#E:ND/RL:ND/RC:ND)", r[3]);
		Assert.assertEquals("cpe:/a:apache:axis2:1.5.1 cpe:/a:apache:axis2:1.5.2 cpe:/a:apache:axis2:1.5.3 cpe:/a:apache:axis2:1.5.4 cpe:/a:apache:axis2:1.5.5 cpe:/a:apache:axis2:1.5.6 cpe:/a:apache:axis2:1.6 cpe:/a:apache:axis2:1.6.1 cpe:/a:apache:axis2:1.6.2", r[4]);
		Assert.assertEquals("", r[5]);
		Assert.assertEquals("no mitigation known", r[6]);
	}

	@Test
	public void testCrawlVulDBRequest2_3() throws IOException {

		final String url = "https://vuldb.com/?id.62731";
		byte[] encoded = Files.readAllBytes(Paths.get("src/test/resources/r2_3.html"));
		String[] r = Crawly.crawlVulDBRequest2(Jsoup.parse(new String(encoded, StandardCharsets.UTF_8)), url);

		for (String string : r) {
			System.out.println("string: " + string);
		}

		Assert.assertEquals(url, r[0]);
		Assert.assertEquals("", r[1]);
		Assert.assertEquals("", r[2]);
		Assert.assertEquals("", r[3]);
		Assert.assertEquals("", r[4]);
		Assert.assertEquals("", r[5]);
		Assert.assertEquals("", r[6]);
	}	
	
}
