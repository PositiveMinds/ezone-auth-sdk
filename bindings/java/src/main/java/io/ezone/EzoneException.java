package io.ezone;

public class EzoneException extends Exception {
    private final int statusCode;

    public EzoneException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() { return statusCode; }
}
