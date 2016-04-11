__author__ = 'apektas'
from bs4 import BeautifulSoup
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def hash_search(md5):
    post_headers = {'Accept-Language': 'en-us',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'Keep-Alive',
                    'Accept': 'image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, */*',
                    'user-agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)',
                    'Referer': 'https://www.virustotal.com/en',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Host': 'www.virustotal.com',
                    'Cache-Control': 'no-cache',
                    'Content-Length': 38
                    }

    url = "https://www.virustotal.com/en/search/"

    payload = {'query': md5}

    response = requests.post(url, headers=post_headers, data=payload, verify=False, allow_redirects=False)

    sha256_url = response.headers.get('location', None)

    if sha256_url:
        print(sha256_url)

        get_headers = {'Accept-Language': 'en-US', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'Keep-Alive',
                       'Accept': 'text/html, application/xhtml+xml, */*',
                       'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
                       'Host': 'www.virustotal.com'
                       }

        response = requests.get(sha256_url, headers=get_headers, verify=False)

        # print response.text

        soup = BeautifulSoup(response.text, "html5lib")
        av_results = soup.findAll("table", {"id": "antivirus-results"})
        additional_info = soup.findAll("div", {"id": "file-details", "class": "extra-info"})
        first_submission = additional_info[0].find_all("div", {"class": "enum-container"})[1].\
                            find("div", {"class": "enum"}).text.splitlines()[2].strip()

        print("First submission: " + first_submission)
        # print(additional_info)

        headers = ""
        av_labels = ""

        for result in av_results:
            headers = result.thead
            av_labels = result.tbody

        # print headers
        # print av_labels.find_all('tr')[2:]:
        # print av_labels

        for tr in headers.find_all('tr'):
            tds = tr.find_all('th')
            print(tds[0].text.strip() + ":" + tds[1].text.strip() + ":" + tds[2].text.strip())

        for tr in av_labels.find_all('tr'):
            tds = tr.find_all('td')
            print(tds[0].text.strip() + ":" + tds[1].text.strip() + ":" +  tds[2].text.strip())

hash_search('4bae0e4a4d6cea1b005bd8cf91346db3')


# fp = open('VirusShare_Android_20140324.md5')
#
# count = 1
# line = fp.readline()
# while line:
#     try:
#         #if not line.startswith("#"):
#         md5 = line.strip()
#         print("{}-####################".format(count))
#         print(md5)
#         hash_search(md5)
#         count += 1
#         line = fp.readline()
#     except Exception as e:
#         print("Exception: " + str(count))
#
# fp.close()