package com.justinluoma;

import java.io.Console;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

public class HaveIBeenPwnedAPI {
    private static final String API_ENDPOINT = "https://api.pwnedpasswords.com/range/";
    private static final HttpResponse.BodyHandler<String> asString = HttpResponse.BodyHandlers.ofString();
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public static void main(String[] args) {
        String sha;
        try {
            char[] password = getPassword();
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            byte[] shaBytes = messageDigest.digest(toBytes(password));
            StringBuilder sb = new StringBuilder();
            for (byte b : shaBytes) {
                sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            }
            Arrays.fill(password, '\u0000');
            sha = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        var HTTP_REQUEST = HttpRequest.newBuilder()
                .uri(URI.create(
                        API_ENDPOINT + sha.substring(0, 5)
                ))
                .timeout(Duration.ofMinutes(1))
                .build();
        HttpResponse HTTP_RESPONSE;
        try {
            HTTP_RESPONSE = HTTP_CLIENT.send(HTTP_REQUEST, asString);
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return;
        }
        if (HTTP_RESPONSE.statusCode() != 200) {
            System.out.printf("Got status code: %d", HTTP_RESPONSE.statusCode());
            return;
        }
        String body = HTTP_RESPONSE.body().toString();
        List<String> hashes = Arrays.asList(body.split("\\r?\\n"));
        Predicate<String> hash = h -> h.toUpperCase().startsWith(sha.toUpperCase().substring(5));
        boolean contains = hashes.parallelStream().anyMatch(hash);
        if (contains) {
            System.out.println("Password compromised");
        } else {
            System.out.println("Password not compromised");
        }
    }

    private static char[] getPassword() {
        try {
            Console console = System.console();
            if (console != null) {
                return console.readPassword("Password: ");
            } else {
                System.out.println("No console");
                System.exit(1);
            }
        } catch (NullPointerException e) {
            e.printStackTrace();
        }
        return new char[0];
    }

    private static byte[] toBytes(char[] chars) {
        CharBuffer charBuffer = CharBuffer.wrap(chars);
        ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
        return bytes;
    }
}