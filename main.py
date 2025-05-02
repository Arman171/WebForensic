import argparse
from main import scrape_emails
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import email_validator
import logging
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_emails(emails):
    """Validate a list of emails using email_validator."""
    validated = []
    for email in emails:
        try:
            # Normalize and validate the email
            valid = email_validator.validate_email(email)
            validated.append(valid.email)
        except email_validator.EmailNotValidError:
            logging.warning(f"Invalid email: {email}")
    return validated

def scrape_emails_from_url(url, max_depth=0, current_depth=0, base_domain=None, visited_urls=None):
    """Scrape emails from a URL, optionally crawling sub-pages up to max_depth."""
    if visited_urls is None:
        visited_urls = set()
    
    if current_depth > max_depth or url in visited_urls:
        return set()
    
    visited_urls.add(url)
    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Chrome(options=options)
    
    try:
        driver.get(url)
        # Wait for the page to fully load
        WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
        
        html = driver.page_source
        emails = scrape_emails(html)
        logging.info(f"Found {len(emails)} emails on {url}")
        
        # If crawling is enabled, find links to sub-pages
        if max_depth > 0 and current_depth < max_depth:
            links = driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                href = link.get_attribute("href")
                if href and base_domain in href and href not in visited_urls:
                    sub_emails = scrape_emails_from_url(href, max_depth, current_depth + 1, base_domain, visited_urls)
                    emails.update(sub_emails)
        
        return emails
    except Exception as e:
        logging.error(f"Error scraping {url}: {e}")
        return set()
    finally:
        driver.quit()

def main():
    parser = argparse.ArgumentParser(description="Professional Email Scraper")
    parser.add_argument("url", help="The URL to scrape emails from")
    parser.add_argument("--output", help="Output file to save emails")
    parser.add_argument("--depth", type=int, default=0, help="Maximum depth for sub-page crawling (0 for single page)")
    args = parser.parse_args()
    
    # Extract base domain for sub-page crawling
    parsed_url = urlparse(args.url)
    base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # Scrape emails
    all_emails = scrape_emails_from_url(args.url, max_depth=args.depth, base_domain=base_domain)
    
    # Validate emails
    validated_emails = validate_emails(all_emails)
    
    # Save to output file if specified
    if args.output:
        with open(args.output, 'w') as f:
            for email in validated_emails:
                f.write(email + '\n')
        logging.info(f"Emails saved to {args.output}")
    
    # Print scraped emails
    logging.info("Scraped emails:")
    for email in validated_emails:
        print(email)

if __name__ == "__main__":
    main()
 