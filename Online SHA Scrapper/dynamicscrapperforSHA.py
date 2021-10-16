import requests
from bs4 import BeautifulSoup
import re
import xlwt

#Sending request to a url and parsing the content using beautifulsoup
#the output of soup variable will be the html tagged data.
#soup.text will give use the text values of all tags.

#res = requests.get('https://bazaar.abuse.ch/browse/')
url=input("Enter the URL to extract SHA256 value on the page: ")
res=requests.get(url)
soup = BeautifulSoup(res.content, 'html.parser')

#Finding the SHA256 using regex in the page text from soup
shas = re.findall("[A-Fa-f0-9]{64}",soup.text)
print(shas)
print('Count of SHA256 samples found is', len(shas))

#Writing the list of SHA256 Samples into excel file using xlwt library
book = xlwt.Workbook()
sheet1 = book.add_sheet('sheet1')
sheet1.write(0,0,'SHA256 of Malware Sample')
for i,e in enumerate(shas):
    sheet1.write(i+1,0,e)
name = "sha256samples.xls"
book.save(name)
