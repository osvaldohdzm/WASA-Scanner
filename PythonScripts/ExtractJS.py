import requests
from bs4 import BeautifulSoup
import argparse


def page_javaScript(page_html):

    #list all the scripts tags
    all_script_tags = page_html.find_all("script")

    #filtering Internal and External JavaScript of page_html
    external_js = list(filter(lambda script:script.has_attr("src"), all_script_tags))
    internal_js = list(filter(lambda script: not script.has_attr("src"), all_script_tags))

    #print the number of Internal and External JavaScript
    print(f"{response.url} page has {len(external_js)} External JS Files")
    print(f"{response.url} page has {len(internal_js)} Internal JS  Code")

    #write internal JavaScript in internal_script.js file
    with open("internal_script.js", "w") as file:
        for index, js_code in enumerate(internal_js):
            file.write(f"\n  //{index+1} script\n")
            file.write(js_code.string)

    #write External JavaScript Source in external_script.txt file
    with open("external_script.txt", "w") as file:
        for index, script_tag in enumerate(external_js):
            file.write(f"{script_tag.get('src')} \n")
            print(index+1,"--------->", script_tag.get("src"))


parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--host', required=True)
args = vars(parser.parse_args())
url = args['host']


#send get request to the url
response = requests.get(url)

#parse the response HTML page
page_html = BeautifulSoup(response.text, 'html.parser')

#extract JavaScript
page_javaScript(page_html)
