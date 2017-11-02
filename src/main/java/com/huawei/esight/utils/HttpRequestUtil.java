package com.huawei.esight.utils;

import com.huawei.esight.exception.EsightException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.xml.SourceHttpMessageConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class HttpRequestUtil {

  private static RestTemplate restTemplate;
  
  private static final Logger LOGGER = Logger.getLogger(HttpRequestUtil.class.getSimpleName());

  private static final String CODE_ESIGHT_CONNECT_EXCEPTION = "-80011";
  
  static {
    System.setProperty("https.protocols", "TLSv1.2,TLSv1.1,TLSv1");
    
    try {
      SSLUtil.turnOffSslChecking();
    } catch (KeyManagementException e) {
      LOGGER.info(e.getMessage());
    } catch (NoSuchAlgorithmException e) {
      LOGGER.info(e.getMessage());
    }
    
    final HostnameVerifier PROMISCUOUS_VERIFIER = new HostnameVerifier() {
      public boolean verify(String s, SSLSession sslSession) {
        return true;
      }
    };
    
    restTemplate = new RestTemplate();
    restTemplate.setRequestFactory(new SimpleClientHttpRequestFactory() {
      @Override
      protected void prepareConnection(HttpURLConnection connection, String httpMethod) 
          throws IOException {
        
        if (connection instanceof HttpsURLConnection) {
          ((HttpsURLConnection) connection).setHostnameVerifier(PROMISCUOUS_VERIFIER);
        }
        super.prepareConnection(connection, httpMethod);
      }
    });
    List<HttpMessageConverter<?>> list = new ArrayList<HttpMessageConverter<?>>();
    list.add(new GsonHttpMessageConverter());
    list.add(new FormHttpMessageConverter());
    list.add(new SourceHttpMessageConverter());
    list.add(new StringHttpMessageConverter());
    restTemplate.setMessageConverters(list);
  }
  
  /**
   *
   * @param url
   * @param method
   * @param headers
   * @param body
   * @param responseType
   * @param <T>
   * @return
   */
  public static <T> ResponseEntity<T> requestWithBody(String url, HttpMethod method, MultiValueMap<String,String> headers,
      String body, Class<T> responseType) {
    HttpEntity<String> requestEntity = new HttpEntity<String>(body, headers);
    
    // mask request header
//    Map<String, Object> outputMap = null;
//    if (headers != null && !headers.isEmpty()) {
//      outputMap = new HashMap<String, Object>(headers);
//      for (Map.Entry key : outputMap.entrySet()) {
//        if (StringUtil.isSensitiveKey(key.getKey().toString())) {
//          Object value = outputMap.get(key.getValue());
//          outputMap.put(key.getKey().toString(), StringUtil.maskValue(value == null ? null : value.toString()));
//        }
//      }
//    }
//
//    String bodyPrint = body;
//    LOGGER.info(method.toString() + " Request " + url + ", headers: " + outputMap + ", body: " +
//        (bodyPrint == null ? "" : bodyPrint.replaceAll("password=[^&]*", "password=******").replaceAll("Password%22%3A%22[^&]*", "Password=******")));
    ResponseEntity<T> responseEntity = restTemplate.exchange(url, method, requestEntity, responseType);
    if (responseEntity == null) {
        throw new EsightException(CODE_ESIGHT_CONNECT_EXCEPTION, "Esight not found error");
    }

    // mask response body
//    if (HttpMethod.PUT == method && url != null && url.endsWith(DefaultOpenIdProvider.SIGNIN_URL)) {
//      LOGGER.info("Response: " + responseEntity.getStatusCode().value() + "{******}");
//    } else {
//      LOGGER.info("Response: " + responseEntity.getStatusCode().value() + responseEntity.getBody().toString());
//    }
    
    if (responseEntity.getStatusCode().value() > 400 && responseEntity.getStatusCode().value() <= 600) {
      throw new EsightException(responseEntity.getStatusCode().name(), "Esight error");
    }
    return responseEntity;
  }
  
  /**
   * Return key=value param concat by &, value is encoded
   */
  public static String concatParamAndEncode(Map<String, String> paramMap) {
    if (paramMap == null || paramMap.isEmpty()) return "";
    StringBuilder buff = new StringBuilder();
    for (Map.Entry<String, String> entry : paramMap.entrySet()) {
      if (buff.length() > 0) buff.append("&");
      buff.append(entry.getKey()).append("=").append(encode(entry.getValue()));
    }
    return buff.toString();
  }
  
  /**
   * Return key=value param concat by &
   */
  public static String concatParam(Map<String, String> paramMap) {
    if (paramMap == null || paramMap.isEmpty()) return "";
    StringBuilder buff = new StringBuilder();
    for (Map.Entry<String, String> entry : paramMap.entrySet()) {
      if (buff.length() > 0) buff.append("&");
      buff.append(entry.getKey()).append("=").append(entry.getValue());
    }
    return buff.toString();
  }
  
  private static String encode(String str) {
    try {
      return URLEncoder.encode(str, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new EsightException("Esight URL Encode error");
    }
  }
  
  static class SSLUtil {
    
    private static final TrustManager[] UNQUESTIONING_TRUST_MANAGER = new TrustManager[]{
        new X509TrustManager() {
          public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
          }
          
          public void checkClientTrusted(X509Certificate[] certs, String authType) {
          }
          
          public void checkServerTrusted(X509Certificate[] certs, String authType) {
          }
        }
    };
    
    public static void turnOffSslChecking() 
        throws NoSuchAlgorithmException, KeyManagementException {
      // Install the all-trusting trust manager
      final SSLContext sc = SSLContext.getInstance("SSL");
      sc.init(null, UNQUESTIONING_TRUST_MANAGER, null);
      HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
    
    public static void turnOnSslChecking() throws KeyManagementException, NoSuchAlgorithmException {
      // Return it to the initial state (discovered by reflection, now hardcoded)
      SSLContext.getInstance("SSL").init(null, null, null);
    }
    
    private SSLUtil() {
      throw new UnsupportedOperationException("Do not instantiate libraries.");
    }
  }

}

