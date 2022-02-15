from Wappalyzer import Wappalyzer, WebPage

webpage = WebPage.new_from_url('https://portalesqa.sre.gob.mx/47agoea/')
wappalyzer = Wappalyzer.latest()
text = wappalyzer.analyze_with_versions_and_categories(webpage)
print(text)
