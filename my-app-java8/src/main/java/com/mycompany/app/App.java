package com.mycompany.app;

import java.util.ArrayList;
import java.util.List;

/**
 * Hello world!
 *
 */
public class App {
	public static void main(String[] args) {
		List<String> words = new ArrayList<>();
    	words.add("Hello");
    	words.add("World!");
    	// This will throw a NoSuchMethodError when
    	// executed in Java 8:
    	// List.of("Hello", "World!");
        words.forEach(System.out::println);
	}
}
