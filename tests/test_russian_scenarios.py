from email.message import EmailMessage
import pytest

from antiphish.analyzer import Analyzer
from antiphish.models import Verdict


def mail(sender, subject, body):
    message=EmailMessage()
    message['From']=sender
    message['Subject']=subject
    message.set_content(body,subtype='html',charset='utf-8')
    return message.as_bytes()


@pytest.mark.parametrize('sender,subject,body',[
 ('Лояльность Сбербанк <gift@external.example>','Ваш подарок',"<h1>СберБанк</h1><p>Вы получили подарок 5000 рублей!</p><a href='https://external.example/claim'>Получить подарок</a>"),
 ('Портал Госуслуги <notify@external.example>','Опрос',"<p>За участие — 5000 рублей</p><a href='https://external.example/survey'>Открыть анкету</a>"),
 ('Ozon <notify@external.example>','Выплата',"<h1>OZON</h1><p>Вы получили 206000 рублей. Готово к выводу.</p><a href='https://clck.ru/claim'>Получить деньги</a>"),
 ('Т-Банк <invest@external.example>','Инвестиции',"<h1>Т-Банк</h1><p>Инвестиции, +25% в день, доход 21000 рублей.</p><a href='https://external.example/invest'>Пройти тест</a>"),
 ('Минцифры <notify@external.example>','Доверенность',"<p>Если вы не оформляли доверенность, перевод денежных средств. Обратитесь в отдел безопасности.</p><a href='https://t.me/fake_help'>Перейти в Telegram</a>"),
 ('Wildberries <notify@external.example>','Приз',"<p>Wildberries: вы выиграли приз!</p><a href='https://docs.google.com/spreadsheets/d/e/campaign/pubhtml'>Получить свой подарок</a>"),
 ('М.Видео <promo@external.example>','Скидка',"<h1>М.Видео</h1><p>Скидка 50% на весь ассортимент, только сегодня!</p><a href='https://external.example/cart'>Использовать промокод</a>"),
])
def test_unverified_russian_scenarios_raise_review_without_inventing_secret_theft(empty_kb,sender,subject,body):
    r=Analyzer(empty_kb).analyze(mail(sender,subject,body),name='mail.eml')
    assert r.verdict==Verdict.SUSPICIOUS
    assert 'PHISHING_FORM_ROUTE' not in {e.code for e in r.reason_codes}


@pytest.mark.parametrize('sender,subject,body',[
 ('СберБанк <info@sberbank.ru>','Программа лояльности',"<h1>СберБанк</h1><p>Вы получили бонус 5000 рублей.</p><a href='https://sberbank.ru/loyalty'>Получить подарок</a>"),
 ('Т-Банк <info@tbank.ru>','Инвестиции',"<h1>Т-Банк</h1><p>Инвестиции: за прошлый год доходность составила 25%, будущая не гарантирована.</p><a href='https://tbank.ru/invest'>Открыть счёт</a>"),
 ('Ozon <promo@ozon.ru>','Бонусы',"<h1>OZON</h1><p>Вы получили 5000 бонусов за покупки.</p><a href='https://ozon.ru/account'>Получить бонус</a>"),
 ('Новости <editor@news.example>','СберБанк',"<h1>Новости</h1><p>СберБанк предупреждает о мошенниках, обещающих инвестиции с доходом 25% в день.</p><a href='https://news.example/story'>Читать новость</a>"),
 ('Бухгалтерия <accounting@corp.ru>','Срочно оплатить счет',"<p>Оплатите счёт согласно договору, реквизиты прежние.</p><a href='https://docs.google.com/document/d/invoice'>Открыть документ</a>"),
 ('Рассылка <sender@vendor.example>','Тренинг Microsoft',"<h1>Тренинг Microsoft</h1><p>Никогда не сообщайте пароль. Материалы обучения.</p><a href='https://vendor.example/training'>Зарегистрироваться</a>"),
 ('Mail.ru <support@mail.ru>','Обновление пароля',"<h1>Mail.ru</h1><p>Подтвердите пароль в настройках аккаунта.</p><a href='https://account.mail.ru/security'>Открыть настройки</a>"),
 ('Госуслуги <info@gosuslugi.ru>','Доверенность',"<h1>Госуслуги</h1><p>Если вы не оформляли доверенность, проверьте личный кабинет.</p><a href='https://gosuslugi.ru/account'>Открыть кабинет</a>"),
 ('Исследования <survey@research.example>','Опрос',"<p>За участие — 5000 рублей. Исследование профессионалов.</p><a href='https://research.example/survey'>Открыть анкету</a>"),
])
def test_russian_hard_negatives_are_not_flagged(empty_kb,sender,subject,body):
    r=Analyzer(empty_kb).analyze(mail(sender,subject,body),name='mail.eml')
    assert r.verdict==Verdict.NOT_DETECTED


def test_spoofed_official_from_is_not_an_authentication_proof(empty_kb):
    body="<h1>СберБанк</h1><p>Вы получили подарок 5000 рублей!</p><a href='https://evil.example/claim'>Получить подарок</a>"
    assert Analyzer(empty_kb).analyze(mail('СберБанк <info@sberbank.ru>','Подарок',body),name='mail.eml').verdict==Verdict.SUSPICIOUS


def test_mixed_alphabets_in_russian_lure_are_normalized(empty_kb):
    body="<h1>BTБ Бaнк Oнлaйн</h1><p>Ηeοбxοдимο οбнοвить дaнныe в личнοм κaбинeтe.</p><a href='https://evil.example/account'>Обнoвить дaнныe</a>"
    assert Analyzer(empty_kb).analyze(mail('ВТБ <noreply@external.example>','Обновление данных',body),name='mail.eml').verdict==Verdict.SUSPICIOUS


@pytest.mark.parametrize('host,expected',[('evil.example',Verdict.SUSPICIOUS),('sberbank.ru',Verdict.NOT_DETECTED)])
def test_non_cash_reward_is_analyzed_with_destination(empty_kb,host,expected):
    body=f"<h1>Сбербанк</h1><p>Ваш ваучер на 100 литров топлива готов.</p><a href='https://{host}/loyalty'>Получить ваучер</a>"
    assert Analyzer(empty_kb).analyze(mail('Сбербанк <info@sberbank.ru>','Ваучер',body),name='mail.eml').verdict==expected


def test_mixed_corrupt_block_retains_russian_brand_words():
    from antiphish.extractors import repair_mojibake
    corrupt='Т-Банк'.encode('utf-8').decode('latin-1')
    investment='Инвестиции'.encode('utf-8').decode('latin-1')
    text='Русский текст '+corrupt+' '+investment+' Ð\u0080Ñ broken tail 😀'
    result=repair_mojibake(text)
    assert 'Т-Банк' in result and 'Инвестиции' in result


def test_social_login_button_does_not_claim_ownership_of_local_password(empty_kb):
    body = "<title>Вход в Личный кабинет</title><h1>Вход</h1><form action='/login' method=post><input type=password><button>Войти</button></form><a href='https://accounts.google.com/'>Войти через Google</a><button>Microsoft</button><footer>Яндекс</footer>".encode()
    report = Analyzer(empty_kb).analyze(body, name="corporate.html", base_url="https://corp.example/login")
    assert report.verdict == Verdict.NOT_DETECTED
    assert not report.pages[0].claimed_brands


@pytest.mark.parametrize('url,expected',[
    ('https://accounts.google.com/signin', Verdict.NOT_DETECTED),
    ('https://docs.google.com/forms/d/account', Verdict.PHISHING),
    ('https://attacker.googleusercontent.com/login', Verdict.PHISHING),
])
def test_cloud_hosting_is_not_google_account_authentication(empty_kb, url, expected):
    body = b"<title>Gmail sign in</title><h1>Google Account</h1><form action='/collect' method=post><input type=password></form>"
    assert Analyzer(empty_kb).analyze(body, name="account.html", base_url=url).verdict == expected


def test_hidden_disabled_control_is_not_a_visible_authentication_form(empty_kb):
    body = "<h1>Статья</h1><div hidden><span>СберБанк</span> Google</div><form action='/search'><input disabled type=password></form>".encode()
    report = Analyzer(empty_kb).analyze(body, name="article.html", base_url="https://news.example/")
    assert report.verdict == Verdict.NOT_DETECTED
    assert not report.pages[0].forms


def test_password_expiry_topic_in_long_newsletter_is_not_a_request(empty_kb):
    body = ("<title>Техническая рассылка</title><h1>Новости</h1><p>" + "Технические новости. " * 100 + "</p><a href='https://support.microsoft.com/help'>How to Log On If Your Password Expires</a>").encode()
    report = Analyzer(empty_kb).analyze(body, name="newsletter.html")
    assert report.verdict == Verdict.NOT_DETECTED


def test_learned_clone_cannot_warn_on_real_issuer(empty_kb, tmp_path):
    from antiphish.templates import learn_file
    body = "<h1>СберБанк</h1><p>Вход в личный кабинет</p><form action='/login' method=post><input type=password></form>".encode()
    source = tmp_path / "clone.html"
    source.write_bytes(body)
    learn_file(source, empty_kb, "phishing", "reviewed-clone")
    analyzer = Analyzer(empty_kb)
    genuine = analyzer.analyze(body, name="login.html", base_url="https://online.sberbank.ru/login")
    fake = analyzer.analyze(body, name="login.html", base_url="https://fake.example/login")
    assert genuine.verdict == Verdict.NOT_DETECTED
    assert "CAMPAIGN_TEMPLATE_MATCH" not in {e.code for e in genuine.reason_codes}
    assert fake.verdict == Verdict.PHISHING
