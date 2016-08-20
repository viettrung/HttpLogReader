package com.mse.fu;

import com.mysql.jdbc.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.sql.*;
import java.text.DecimalFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogReader {

    static final String LOG_FOLDER = "C:\\Users\\dgvie\\Google Drive\\MSE\\Thesis\\Data\\log_http_apache";
//    static final String LOG_FOLDER = "D:\\New folder\\log_http_apache";

    static String INSERT_QUERY = "insert into requestlog (clientIP, identity, username, date, time, method, accessURL, accessURLDomain, protocol, statusCode, responseSize, referer, refererDomain, userAgent, hour) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

    static DecimalFormat formatter = new DecimalFormat("#0.00");

    static String getAccessLogRegex()
    {
//        String regex1 = "^([\\d.]+)"; // Client IP
        String regex1 = "^(.+)"; // Client IP
        String regex2 = " (\\S+)"; // -
        String regex3 = " (\\S+)"; // -
        String regex4 = " \\[(.*)\\]"; // Date
        String regex5 = " \"(.+?)\" "; // request method and url
        String regex6 = "(\\d{1,3})"; // HTTP code
        String regex7 = " ([\\d,]+)"; // Number of bytes
        String regex8 = " \"(.*?)\""; // Referer
        String regex9 = " \"(.*?)\""; // Agent

        // ^([\d.]+) (\S+) (\S+) \[(.*)\] "(.+?)" (\d{1,3}) ([\d,]+) "(.*?)" "(.*?)"
        return regex1+regex2+regex3+regex4+regex5+regex6+regex7+regex8+regex9;
    }

    // http://regexr.com/
    // http://www.sghaida.com/parse-apache-access-log-using-java/
    public static void main(String[] args) {

        BufferedReader br = null;
        String currentLine;

        Connection con = null;
        PreparedStatement ps = null;

        int[] result;
        int count;
        try {
            File logFolder = new File(LOG_FOLDER);

            con = DBConnection.getConnection();
            con.setAutoCommit(false);

            ps = con.prepareStatement(INSERT_QUERY);

            long start = System.currentTimeMillis();
            for (File file : logFolder.listFiles()) {
                if (file.getName().endsWith(".log")) {

                    System.out.println(" - " + file.getAbsolutePath());
                    long s = System.currentTimeMillis();

                    br = new BufferedReader(new FileReader(file));
                    count = 0;
                    while ((currentLine = br.readLine()) != null) {
                        count++;
                        getLogObjectFromLine(currentLine.trim().replaceAll(" +", " "), ps);
                        break;
                    }

                    System.out.println("Commit the batch...");
                    result = ps.executeBatch();

                    System.out.print("Number of rows inserted: " + result.length + " | count: " + count);
                    long e = System.currentTimeMillis();
                    System.out.println(" (" + (e - s) / 1000 + "s)");
                    System.out.println("   ======      ");

                    con.commit();
                    break;
                }
            }
            long end = System.currentTimeMillis();
            System.out.println("Time taken: " + (end - start) / 1000);

//            getFeaturesFromUserAgentStr(con);

            if (ps != null) {
                ps.close();
            }
            if (con != null) {
                con.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally{
            try {
                ps.close();
                con.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    private static void getFeaturesFromUserAgentStr(Connection conn) {
        try {
            PreparedStatement ps = conn.prepareStatement("insert into agent(agent_name, os_name, userAgent) values (?, ?, ?)");
            Statement stmt = conn.createStatement();

            String query = "SELECT DISTINCT(userAgent) from requestlog where userAgent not IN (select userAgent from agent)";

            long startQuery = System.currentTimeMillis();
            ResultSet rs = stmt.executeQuery(query);
            long endQuery = System.currentTimeMillis();
            System.out.println("Query time: " + (endQuery-startQuery)/1000);

            System.out.println("Calling API...");
            long startAPICall = System.currentTimeMillis();
            while (rs.next()) {
                String userAgent = rs.getString("userAgent");

                JSONObject json = getJsonFromUserAgentStr(userAgent);

                if (!StringUtils.isNullOrEmpty(json.get("agent_name").toString())) {
                    ps.setString(1, json.get("agent_name").toString());
                } else {
                    ps.setString(1, "unknown");
                }

                if (!StringUtils.isNullOrEmpty(json.get("os_name").toString())) {
                    ps.setString(2, json.get("os_name").toString());
                } else {
                    ps.setString(2, "unknown");
                }
                ps.setString(3, userAgent);

                ps.addBatch();
            }
            long endAPICall = System.currentTimeMillis();
            System.out.println("Time to call API: " + (endAPICall-startAPICall)/1000);

            System.out.println("Executing batch...");
            long startExecuteBatch = System.currentTimeMillis();
//            ps.executeBatch();
            long endExecuteBatch = System.currentTimeMillis();
            System.out.println("Time to call executeBatch: " + (endExecuteBatch-startExecuteBatch)/1000);

//            conn.commit();
            ps.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static void getLogObjectFromLine(String line, PreparedStatement  ps) throws Exception {

        Matcher requestLineMatcher;

        String[] dateTime;

        Matcher m = Pattern.compile(getAccessLogRegex()).matcher(line); // http://stackoverflow.com/questions/3366281/tokenizing-a-string-but-ignoring-delimiters-within-quotes
        while (m.find()) {

//            logObject.setClientIp(m.group(1));
            ps.setString(1, m.group(1));

//            logObject.setIdentity(m.group(2));
            ps.setString(2, m.group(2));

//            logObject.setUsername(m.group(3));
            ps.setString(3, m.group(3));

            dateTime = m.group(4).split("\\s+");
//            logObject.setDate(dateTime[0]);
//            logObject.setTime(dateTime[1]);

            ps.setString(4, dateTime[0]);
            ps.setString(5, dateTime[1]);

            requestLineMatcher = Pattern.compile("([^\\s]*) (.*) ([^\\s]*)").matcher(m.group(5));
            while (requestLineMatcher.find()) {
//                logObject.setMethod(requestLineMatcher.group(1));
                ps.setString(6, requestLineMatcher.group(1));

//                logObject.setAccessUrl(requestLineMatcher.group(2));
                ps.setString(7, requestLineMatcher.group(2));

//                logObject.setAccessUrlDomain(getBaseDomain(logObject.getAccessUrl()));
                ps.setString(8, getBaseDomain(requestLineMatcher.group(2)));

//                logObject.setProtocol(requestLineMatcher.group(3));
                ps.setString(9, requestLineMatcher.group(3));
            }

//            logObject.setStatusCode(m.group(6));
            ps.setString(10, m.group(6));

//            logObject.setResponseSize(m.group(7));
//            ps.setString(11, m.group(7).replaceAll(",", "."));
            Double responseSive = Double.valueOf(m.group(7).replaceAll(",", ""));
            ps.setString(11, formatter.format(responseSive));

//            logObject.setReferer(m.group(8));
            ps.setString(12, m.group(8));
            if (!m.group(8).isEmpty()) {
//                logObject.setRefererDomain(getBaseDomain(logObject.getReferer()));
                ps.setString(13, getBaseDomain(m.group(8)));
            } else {
                ps.setString(13, "");
            }

            // TODO: browser, OS, device type (mobile/desktop)...
            // http://stackoverflow.com/questions/8515161/detecting-device-type-in-a-web-application
            // https://developer.mozilla.org/en-US/docs/Browser_detection_using_the_user_agent
            // http://www.useragentstring.com/pages/api.php
//            logObject.setUserAgent(m.group(9));
            ps.setString(14, m.group(9));
            ps.setString(15, dateTime[1].split(":")[0]);

            ps.addBatch();

        }

    }

    private static String getBaseDomain(String url) {

        String baseDomain = "";
        try {
            URL myUrl = new URL(url);

            String domain = myUrl.getHost();
            baseDomain = domain.startsWith("www.") ? domain.substring(4) : domain;
        } catch (MalformedURLException e) {
//            System.err.println("MalformedURLException: " + e.getMessage());
//            System.out.println(url);
        }
        return baseDomain;
    }

    private static JSONObject getJsonFromUserAgentStr(String userAgent) {

        JSONObject jsonObject = null;
        try {

            URL url = new URL("http://www.useragentstring.com/?uas=" + URLEncoder.encode(userAgent, "UTF-8") + "&getJSON=all");

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
            }

            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));

            String output;
            while ((output = br.readLine()) != null) {
                JSONParser parser = new JSONParser();
                Object obj = parser.parse(output);

                jsonObject = (JSONObject) obj;
            }

            conn.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return jsonObject;
    }
}
