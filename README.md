# Automated SAR Generation System Using OOPS

## Introduction

The **Automated Suspicious Activity Reporting (SAR) System** is a
banking monitoring application developed using **C++ and Object-Oriented
Programming (OOPS)** principles.

The system analyzes transaction data and automatically generates
**Suspicious Activity Reports (SAR)** based on predefined rules such as
large transaction amounts and unusual transaction times.

It also includes a lightweight **HTTP server** that serves a web
interface where users can log in, analyze transactions, and view
reports.

------------------------------------------------------------------------

## Features

-   Automated SAR generation based on transaction rules
-   Web-based dashboard for user interaction
-   Transaction history display
-   Risk score calculation
-   Implementation of core OOPS concepts
-   Simple HTTP server built with Winsock
-   Lightweight single-file implementation

------------------------------------------------------------------------

## Technologies Used

-   C++
-   Object-Oriented Programming (OOPS)
-   Winsock2 (Windows Socket API)
-   HTML / CSS / JavaScript

------------------------------------------------------------------------

## OOPS Concepts Used

-   **Class & Object**
-   **Encapsulation**
-   **Abstraction**
-   **Modularity**

Main Classes: - Transaction - TransactionManager - SARAnalyzer -
PageBuilder - HTTPServer

------------------------------------------------------------------------

## Installation

### Requirements

-   Windows OS
-   C++ Compiler (MinGW or Visual Studio)

### Compile

`g++ sar_system.cpp -lws2_32 -o sar_system`

### Run

`sar_system.exe`

------------------------------------------------------------------------

## Usage

1.  Start the program.
2.  Open a browser and go to:

`http://localhost:9090`

3.  Login using demo credentials:

| Username | Password |
|----------|----------|
| kanchan  | 1234     |
| vedika   | 5678     |

4.  Use the dashboard to:

-   Generate SAR reports
-   View generated reports
-   View transaction history

------------------------------------------------------------------------

## SAR Detection Rules

-   Amount \> 10,000 → Large transaction
-   Amount \> 20,000 → Very high risk transaction
-   Time between 22:00 -- 05:00 → Unusual late-night activity

Each rule contributes to a **risk score out of 100**.

------------------------------------------------------------------------

## Project Structure

Single file project:

`sar_system.cpp`

------------------------------------------------------------------------
