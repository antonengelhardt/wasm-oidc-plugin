from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

from time import sleep
import os
from dotenv import load_dotenv

# Global variables

load_dotenv()

BASE_URL = "http://" + os.getenv("GATEWAY") + ":10000" if os.getenv("GATEWAY") is not None else "http://localhost:10000"
print(BASE_URL)

WASM_OIDC_PLUGIN_TEST_EMAIL = os.getenv("WASM_OIDC_PLUGIN_TEST_EMAIL")
WASM_OIDC_PLUGIN_TEST_PASSWORD = os.getenv("WASM_OIDC_PLUGIN_TEST_PASSWORD")

# Helper functions

def set_chrome_options() -> None:
    """Sets chrome options for Selenium.
    Chrome options for headless browser is enabled."""

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_prefs = {}
    chrome_options.experimental_options["prefs"] = chrome_prefs
    chrome_prefs["profile.default_content_settings"] = {"images": 2}

    return chrome_options

def set_up() -> None:
    """Sets up the Selenium driver."""

    global driver
    if os.getenv("CI") == "true":
        driver = webdriver.Chrome(options=set_chrome_options())
    else:
        driver = webdriver.Chrome()

def login(driver: webdriver) -> None:
    """ Logs in to the application. """

    driver.get(BASE_URL)
    driver.find_element(By.ID, "username").send_keys(WASM_OIDC_PLUGIN_TEST_EMAIL)
    driver.find_element(By.ID, "password").send_keys(WASM_OIDC_PLUGIN_TEST_PASSWORD)
    driver.find_element(By.XPATH, "/html/body/div/main/section/div/div[2]/div/form/div[2]/button").click()

def tear_down() -> None:
    """Tears down the Selenium driver."""

    driver.delete_all_cookies()

    driver.quit()

# Tests
def test_home_page() -> None:
    """Tests if the home page is accessible."""

    set_up()
    driver.get(BASE_URL)
    assert driver.title == "Log in | wasm-oidc-plugin integration tests"
    tear_down()

def test_success() -> None:
    """Tests if the login is successful."""

    set_up()
    login(driver)

    assert driver.current_url == "http://httpbin.org"
    assert driver.get_cookie("oidcSession-0") is not None
    tear_down()

def test_unsuccessful() -> None:
    """Test if the login fails when the wrong credentials are entered."""

    set_up()
    driver.get(BASE_URL)
    driver.find_element(By.ID, "username").send_keys(WASM_OIDC_PLUGIN_TEST_EMAIL)
    driver.find_element(By.ID, "password").send_keys("nottherightpassword")
    driver.find_element(By.XPATH, "/html/body/div/main/section/div/div[2]/div/form/div[2]/button").click()
    assert driver.title == "Log in | wasm-oidc-plugin integration tests"
    tear_down()

# def test_modified_cookie() -> None:
#     """Test if the login fails when the cookie is modified."""

#     set_up()
#     login(driver)

#     driver.delete_all_cookies()
#     print(driver.get_cookies())
#     driver.refresh()
#     assert driver.title == "Log in | wasm-oidc-plugin integration tests"
#     tear_down()

def test_excluded_path() -> None:
    """ Test if the request is allowed when it matches the pattern. """

    set_up()
    driver.get(BASE_URL+"/anything")
    assert driver.title == ""
    tear_down()
