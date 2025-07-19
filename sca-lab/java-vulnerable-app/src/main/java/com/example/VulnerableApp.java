package com.example;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VulnerableApp {
    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);
    
    public static void main(String[] args) {
        logger.info("Aplicación vulnerable iniciada");
        System.out.println("Aplicación con dependencias vulnerables");
    }
}
