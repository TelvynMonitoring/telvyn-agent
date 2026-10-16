package org.bson;

/** Stand-in for the MongoDB driver class, only so IastSinksCheck can be compiled without the driver. It parses nothing. */
public class Document {
    public static Document parse(String json) { return null; }
}
