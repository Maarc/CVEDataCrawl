package org.jboss.crawl;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 * Utility class retrieving relevant meta-data for a list of CVEs.
 *
 * @author Marc
 */
public class Crawly {

	private final static int RETRY_COUNT = 4;

	private final static int TIMEOUT = 20000;

	private final static long PAUSE = 15000l;

	private final static char DELIMITER = ';';

	private final static String NOT_AVAILALBLE = "n/a";

	private final static String USER_AGENT = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-en) AppleWebKit/523.10.3 (KHTML, like Gecko) Version/3.0.4 Safari/523.10";

	/**
	 * Main method
	 *
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {

		final String sourceFile = "libs.csv";
		final String destFile = "libs_updated.csv";
		final String timestamp = Long.toString(System.currentTimeMillis());

		String[] rh = null;
		String[] vuldb = null;
		String cve = null;

		final Map<String, String[]> currentResult = readResultCSV(destFile);
		final Map<String, String[]> result = new HashMap<String, String[]>();

		for (Entry<String, String> e : readCVELibMap(sourceFile).entrySet()) {
			cve = e.getKey();
			String[] r = currentResult.get(cve);
			// TODO add a check on the timestamp
			if (r == null || StringUtils.isEmpty(r[0])) {
				rh = crawlRH(cve);
				vuldb = crawlVulDB(cve);
				result.put(cve, new String[] { StringUtils.isEmpty(vuldb[1]) ? StringUtils.EMPTY : timestamp, vuldb[0], vuldb[1], vuldb[2], vuldb[3], vuldb[4], vuldb[5], vuldb[6], rh[0], rh[1], rh[2], e.getValue() });
			} else {
				result.put(cve, r);
			}
		}
		writeResultCSV(destFile, result);
	}

	/**
	 * Write the result in a CSV file.
	 *
	 * @param destFile
	 * @param result
	 * @throws IOException
	 */
	private static void writeResultCSV(final String destFile, final Map<String, String[]> result) throws IOException {

		try (final Writer fileWriter = new FileWriter(destFile);
			 final CSVPrinter csvFilePrinter = new CSVPrinter(fileWriter, CSVFormat.DEFAULT.withDelimiter(DELIMITER));) {
			// CSV header
			csvFilePrinter.printRecord("CVE", "Timestamp", "VulDB URL", "Exploit Price", "CVSS 2 Base", "CVSS 2 Temp", "CPE(s)", "Status", "Solution", "RH Bugzilla URL", "Bugzilla Status", "Bugzilla fix in", "Libraries affected");
			for (Entry<String, String[]> e : result.entrySet()) {
				try {
					List<String> l = new ArrayList<String>();
					l.add(e.getKey());
					l.addAll(Arrays.asList(e.getValue()));
					csvFilePrinter.printRecord(l.toArray());
				} catch (Throwable t) {
					t.printStackTrace(System.out);
				}
			}
		}
	}

	/**
	 * Read the CSV file listing all CSV and their related CVE and build a map
	 * containing all libraries affected by every CVE.
	 *
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	private static final Map<String, String> readCVELibMap(final String filename) throws IOException {

		Map<String, String> m = new HashMap<String, String>();
		Reader in = new FileReader(filename);
		for (CSVRecord record : CSVFormat.DEFAULT.withDelimiter(';').parse(in)) {

			String lib = record.get(0);
			String cve = record.get(1);

			if (m.containsKey(cve)) {
				m.put(cve, lib + " " + m.get(cve));
			} else {
				m.put(cve, lib);
			}
		}
		return m;
	}

	/**
	 * Read the CSV file listing all CSV and their related CVE and build a map
	 * containing all libraries affected by every CVE.
	 *
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	private static final Map<String, String[]> readResultCSV(final String filename) {

		final Map<String, String[]> result = new HashMap<String, String[]>();
		try (Reader in = new FileReader(filename)) {
			for (CSVRecord r : CSVFormat.DEFAULT.withDelimiter(';').parse(in)) {
				Iterator<String> i = r.iterator();
				i.next();
				List<String> l = new ArrayList<String>();
				while (i.hasNext()) {
					l.add(i.next());
				}
				result.put(r.get(0), l.stream().toArray(String[]::new));
			}
		} catch (Throwable t) {
			t.printStackTrace(System.out);
		}
		return result;
	}

	/**
	 * Wait a while.
	 */
	private static final void pause(int i) {
		try {
			Thread.sleep(i * PAUSE);
		} catch (InterruptedException e) {
			e.printStackTrace(System.out);
		}
	}

	/**
	 * Crawl https://vuldb.com to retrieve the available information about the
	 * specific CVE.
	 *
	 * @param cve
	 * @return
	 */
	private static final String[] crawlVulDB(String cve) {

		System.out.println(">>> crawlVulDB(" + cve + ")");

		String infoUrl = null;
		int retryCount = RETRY_COUNT;

		// Retry
		while (infoUrl == null) {
			infoUrl = crawlVulDBRequest1(cve);

			if (infoUrl == null) {
				if (retryCount == 0) {
					infoUrl = NOT_AVAILALBLE;
				} else {
					retryCount--;
					pause(RETRY_COUNT - retryCount);
				}
			}
		}

		pause(1);

		String[] result = null;
		retryCount = RETRY_COUNT;
		if (NOT_AVAILALBLE.equals(infoUrl)) {
			result = new String[] { infoUrl, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY };
		} else {
			// Retry
			while (result == null) {
				result = crawlVulDBRequest2(infoUrl);

				if (result == null) {
					if (retryCount == 0) {
						result = new String[] { infoUrl, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY, StringUtils.EMPTY };
					} else {
						retryCount--;
						pause(RETRY_COUNT - retryCount);
					}
				}

			}
		}

		System.out.println("<<< crawlVulDB(" + cve + ")");
		return result;
	}

	/**
	 *
	 * @param cve
	 * @return
	 */
	private static String crawlVulDBRequest1(String cve) {

		System.out.println(">>> crawlVulDBRequest1(" + cve + ")");
		String infoUrl = null;
		try {
			Document vuldDB = Jsoup.connect("https://vuldb.com/?search").data("cve", cve).userAgent(USER_AGENT).timeout(TIMEOUT).validateTLSCertificates(false).post();

			for (Element link : vuldDB.select("a[href]")) {
				String url = link.attr("href");
				if (url != null && url.startsWith("?id.")) {
					infoUrl = "https://vuldb.com/" + url;
					break;
				}
			}

		} catch (Throwable t) {
			t.printStackTrace(System.out);
		}

		System.out.println("<<< crawlVulDBRequest1(" + cve + ") " + infoUrl);
		return infoUrl;
	}

	/**
	 *
	 * @param infoUrl
	 * @return
	 */
	private static String[] crawlVulDBRequest2(String infoUrl) {
		String[] r = null;
		try {
			 r = crawlVulDBRequest2(Jsoup.connect(infoUrl).userAgent(USER_AGENT).timeout(TIMEOUT).validateTLSCertificates(false).get(), infoUrl);
		} catch (Throwable t) {
			t.printStackTrace(System.out);
		}
		return r;
	}

	/**
	 *
	 * @param c
	 * @param infoUrl
	 * @return
	 */
	static String[] crawlVulDBRequest2(Document vuldDB, String infoUrl) {

		System.out.println(">>> crawlVulDBRequest2(" + infoUrl + ")");

		String recommendation = "";
		String status = "";
		String price = "";
		String cvssBase = "";
		String cvssTemp = "";
		String cpes = "";

		String[] result = null;
		try {
			Elements s = vuldDB.select("table.vultop > tbody > tr > td");
			// cvssTemp= s.get(0).text();
			if(s.size()>0) {

				price = s.get(1).text();

				// Parsing the vulnerability page manually ...
				Elements select = vuldDB.select("[class=\"vuln\"");
				String text = select.first().html();
				for (String h2 : text.split("<h2")) {

					if (StringUtils.contains(h2, "Countermeasures")) {
						for (String el : h2.split("<br>")) {
							if (StringUtils.contains(el, "Recommended")) {
								recommendation = StringUtils.trimToEmpty(el.split(": ")[1]);
							} else if (StringUtils.contains(el, "Status")) {
								status = StringUtils.trimToEmpty(el.split(": ")[1]);
							} else if (StringUtils.contains(el, "Upgrade<") | StringUtils.contains(el, "Patch")) {
								String info = StringUtils.trimToEmpty(el.split(": ")[1]);
								if (StringUtils.contains(info, "href=")) {
									info = StringUtils.substringBetween(info, "href=\"", "\"");
								} else if (!StringUtils.contains(info, "Patch")) {
									recommendation += " [" + info + "]";
								}
							}
						}
					} else if (StringUtils.contains(h2, "cvss") & !StringUtils.contains(h2, "vultop")) {

						for (String el : h2.split("<br>")) {
							if (StringUtils.contains(el, "Base Score")) {
								cvssBase = StringUtils.trimToEmpty(el.split(": ")[1]);
								cvssBase = StringUtils.substringBefore(cvssBase, ")") + ")";
							} else if (StringUtils.contains(el, "Temp Score")) {
								cvssTemp = StringUtils.trimToEmpty(el.split(": ")[1]);
								cvssTemp = StringUtils.substringBefore(cvssTemp, ")") + ")";
							}
						}

					} else if (StringUtils.contains(h2, "CPE")) {
						for (String el : h2.split("<a href=")) {
							if (StringUtils.contains(el, "cpe:")) {
								cpes += "cpe:" + StringUtils.substringBetween(el, "cpe:", "<") + " ";
							}
						}
					}
				}
			}

			result = new String[] { infoUrl, price, cvssBase, cvssTemp, StringUtils.trimToEmpty(cpes), status, recommendation };

		} catch (Throwable t) {
			t.printStackTrace(System.out);
		}
		System.out.println("<<< crawlVulDBRequest2(" + infoUrl + ")");
		return result;
	}

	/**
	 * Crawl https://access.redhat.com/security/cve to retrieve the available
	 * information about the specific CVE.
	 *
	 * @param cve
	 * @return
	 */
	private static final String[] crawlRH(String cve) {

		System.out.println(">>> crawlRH(" + cve + ")");
		String bugzillaUrl = "n/a";
		String fixText = "";
		String status = "";

		try {
			Document rhCve = Jsoup.connect("https://access.redhat.com/security/cve/" + cve).userAgent(USER_AGENT).timeout(TIMEOUT).validateTLSCertificates(false).get();
			for (Element link : rhCve.select("a[href]")) {
				String url = link.attr("href");
				// Retrieve the url to the bugzilla entry
				if (url != null && url.contains("bugzilla")) {
					bugzillaUrl = url;
					Document bugzilla = Jsoup.connect(url).userAgent(USER_AGENT).timeout(TIMEOUT).validateTLSCertificates(false).get();
					fixText = bugzilla.getElementById("field_container_cf_fixed_in").text();
					status = bugzilla.getElementById("static_bug_status").text();
					break;
				}
			}
		} catch (Throwable t) {
			t.printStackTrace(System.out);
		}
		System.out.println("<<< crawlRH(" + cve + ")");
		return new String[] { StringUtils.trimToEmpty(bugzillaUrl), StringUtils.trimToEmpty(status), StringUtils.trimToEmpty(fixText) };
	}

}
