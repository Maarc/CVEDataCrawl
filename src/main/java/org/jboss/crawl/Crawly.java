package org.jboss.crawl;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

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

	private final static char DELIMITER = ';';

	private final static int TIMEOUT = 20000;

	private final static String USER_AGENT = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-en) AppleWebKit/523.10.3 (KHTML, like Gecko) Version/3.0.4 Safari/523.10";

	/**
	 * Main method
	 *
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {

		final Map<String, String> map = getCVELibMap("libs.csv");
		final Writer fileWriter = new FileWriter("libs_updated.csv");

		final CSVPrinter csvFilePrinter = new CSVPrinter(fileWriter, CSVFormat.DEFAULT.withDelimiter(DELIMITER));

		// CSV header
		csvFilePrinter.printRecord("CVE","VulDB URL","Exploit Price","CVSS 2 Base","CVSS 2 Temp","CPE(s)","Status","Solution","RH Bugzilla URL","Bugzilla Status","Bugzilla fix in","Libraries affected");

		for (String cve : map.keySet()) {
			String[] rh = crawlRH(cve);
			String[] vuldb = crawlVulDB(cve);

			try {
				csvFilePrinter.printRecord(cve, vuldb[0], vuldb[1], vuldb[2], vuldb[3], vuldb[4], vuldb[5], vuldb[6], rh[0], rh[1], rh[2],map.get(cve));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		try {
			fileWriter.flush();
			fileWriter.close();
			csvFilePrinter.close();
		} catch (IOException e) {
			System.out.println("Error while flushing/closing fileWriter/csvPrinter !!!");
			e.printStackTrace();
		}
	}

	/**
	 * Build a map containing all libraries affected by every CVE
	 *
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	private static final Map<String,String> getCVELibMap(String filename) throws IOException {

		Map<String, String> m = new HashMap<String,String>();
		Reader in = new FileReader(filename);
		for (CSVRecord record : CSVFormat.DEFAULT.withDelimiter(';').parse(in)) {

			String lib = record.get(0);
			String cve = record.get(1);

			if(m.containsKey(cve)){
				m.put(cve, lib+" "+m.get(cve));
			} else {
				m.put(cve,lib);
			}
		}

		return m;
	}

	/**
	 * Crawl https://vuldb.com to retrieve the available information about the specific CVE.
	 *
	 * @param cve
	 * @return
	 */
	private static final String[] crawlVulDB(String cve) {

		System.out.println(">>> crawlVulDB(" + cve +")");

		String infoUrl = "n/a";
		String recommendation = "";
		String status = "";
		String price ="";
		String cvssBase = "";
		String cvssTemp = "";
		String cpes= "";
		try {

			Document vuldDB = Jsoup.connect("https://vuldb.com/?search").data("cve",cve).userAgent(USER_AGENT).timeout(TIMEOUT).validateTLSCertificates(false).post();

			for (Element link : vuldDB.select("a[href]")) {
				String url = link.attr("href");
				if (url != null && url.startsWith("?id.")) {
					infoUrl = "https://vuldb.com/"+url;
					break;
				}
			}

			vuldDB = Jsoup.connect(infoUrl).userAgent(USER_AGENT).timeout(TIMEOUT).validateTLSCertificates(false).get();

			Elements s = vuldDB.select("table.vultop > tbody > tr > td");
			//cvssTemp= s.get(0).text();
			price= s.get(1).text();

			// Parsing the vulnerability page manually ...
			Elements select = vuldDB.select("[class=\"vuln\"");
			String text = select.first().html();
			for (String h2 : text.split("<h2>")) {
				if(StringUtils.contains(h2,"Countermeasures")) {
					for (String el : h2.split("<br>")) {
						if(StringUtils.contains(el, "Recommended")){
							recommendation = StringUtils.trimToEmpty(el.split(": ")[1]);
						} else if(StringUtils.contains(el, "Status")){
							status=StringUtils.trimToEmpty(el.split(": ")[1]);
						} else if(StringUtils.contains(el, "Upgrade<") | StringUtils.contains(el, "Patch")){
							String info=StringUtils.trimToEmpty(el.split(": ")[1]);
							if(StringUtils.contains(info, "href=")){
								info=StringUtils.substringBetween(info, "href=\"", "\"");
							} else if(!StringUtils.contains(info, "Patch")){
								recommendation += " ["+info+"]";
							}
						}
					}
				} else if (StringUtils.contains(h2,"CVSS") & !StringUtils.contains(h2,"vultop")) {
					for (String el : h2.split("<br>")) {
						if(StringUtils.contains(el, "Base Score")){
							cvssBase = StringUtils.trimToEmpty(el.split(": ")[1]);
							cvssBase = StringUtils.substringBefore(cvssBase, ")")+")";
						} else if(StringUtils.contains(el, "Temp Score")){
							cvssTemp = StringUtils.trimToEmpty(el.split(": ")[1]);
							cvssTemp = StringUtils.substringBefore(cvssTemp, ")")+")";
						}
					}

				} else if (StringUtils.contains(h2,"CPE")) {
					for (String el : h2.split("<a href=")) {
						if(StringUtils.contains(el,"cpe:")) {
							cpes += "cpe:"+StringUtils.substringBetween(el, "cpe:","<")+" ";
						}
					}
				}
			}

		} catch (Throwable t) {
			t.printStackTrace();
		}

		System.out.println("<<< crawlVulDB(" + cve+")");
		return new String[] { infoUrl, price, cvssBase, cvssTemp, StringUtils.trimToEmpty(cpes), status, recommendation };
	}

	/**
	 * Crawl https://access.redhat.com/security/cve to retrieve the available information about the specific CVE.
	 *
	 * @param cve
	 * @return
	 */
	private static final String[] crawlRH(String cve) {

		System.out.println(">>> crawlRH(" + cve+")");
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
					status= bugzilla.getElementById("static_bug_status").text();
					break;
				}
			}
		} catch (Throwable t) {
			t.printStackTrace();
		}
		System.out.println("<<< crawlRH(" + cve+")");
		return new String[] {StringUtils.trimToEmpty(bugzillaUrl), StringUtils.trimToEmpty(status), StringUtils.trimToEmpty(fixText) };
	}

}
