#!/usr/bin/env python3
"""Generate a synthetic corpus of modern (2024-2026) US SMS spam and ham.

The UCI corpus is 2005-2012 UK spam (ringtones, premium shortcodes); today's
campaigns are delivery/toll phishing, pig-butchering, loans, and political
fundraising. Template grammars with slot-filling give wording variety while
staying label-clean. Deterministic seed for reproducibility.
"""

import csv
import itertools
import random
import sys

random.seed(1729)

FIRST_NAMES = ["Cynthia", "Karen", "Michael", "Jessica", "David", "Amanda", "Robert",
               "Linda", "James", "Maria", "John", "Sarah", "Kevin", "Lisa", "Brian"]
CARRIERS = ["USPS", "UPS", "FedEx", "DHL"]
BANKS = ["Chase", "Bank of America", "Wells Fargo", "Citibank", "Capital One", "US Bank"]
SERVICES = ["Netflix", "Amazon", "Apple", "PayPal", "Venmo", "Spotify", "Hulu", "Disney+"]
TOLLS = ["FasTrak", "E-ZPass", "SunPass", "TxTag", "I-Pass", "Peach Pass"]
DOMAINS_BAD = ["track-fix.top", "pkg-update.xyz", "secure-verify.vip", "acct-help.icu",
               "pay-now.cyou", "redelivery.sbs", "claim-funds.win", "quick-cash.cfd",
               "gov-refund.lol", "member-portal.rest", "info-check.click", "bonus4u.buzz"]
AMOUNTS = ["$1.99", "$2,500", "$500", "$6.87", "$11.69", "$3.45", "$5,000", "$750", "$88"]
POLS = ["President Trump", "the DNC", "the RNC", "Democrats", "Republicans", "the GOP",
        "Senator Warren", "Speaker Johnson", "our MAGA team", "Kamala Harris"]
DEADLINES = ["midnight", "our FEC deadline", "the end-of-month deadline", "our fundraising deadline", "11:59 PM"]
MATCHES = ["4X-MATCHED", "5x matched", "triple matched", "600% matched", "DOUBLE MATCHED"]

def pick(xs):
    return random.choice(xs)

def url():
    return f"https://{pick(DOMAINS_BAD)}/{''.join(random.choices('abcdefghijklmnop0123456789', k=5))}"

def spam_delivery():
    t = [
        f"{pick(CARRIERS)}: Your package is on hold due to an {pick(['incomplete', 'incorrect', 'invalid'])} address. Update your information at {url()}",
        f"{pick(CARRIERS)}: We were unable to deliver your package. A customs fee of {pick(['$1.99', '$2.99', '$0.99'])} is required: {url()}",
        f"Your package could not be delivered on {random.randint(1,12)}/{random.randint(1,28)}. Confirm your address within {pick(['12', '24', '48'])} hours: {url()}",
        f"{pick(CARRIERS)} notice: your delivery is pending. Redeliver here {url()}",
        f"Final reminder: package {random.randint(10000,99999)} held at facility. Pay redelivery fee {url()}",
    ]
    return pick(t)

def spam_toll():
    t = [
        f"{pick(TOLLS)}: You have an unpaid toll balance of {pick(['$6.87', '$4.15', '$11.69', '$12.51'])}. Avoid a late fee of $50: {url()}",
        f"{pick(TOLLS)} Final Notice: outstanding toll invoice. Pay now to avoid penalties {url()}",
        f"Toll violation notice: your vehicle has an unpaid balance. Settle immediately at {url()}",
    ]
    return pick(t)

def spam_phishing():
    t = [
        f"{pick(SERVICES)}: Your account has been {pick(['suspended', 'locked', 'restricted'])} due to unusual activity. Verify now: {url()}",
        f"{pick(BANKS)}: Your account is locked. Confirm your identity at {url()} immediately.",
        f"{pick(SERVICES)}: your payment was declined. Update your billing information within 24 hours or your account will be deactivated: {url()}",
        f"Your Apple ID was used to sign in on a new device. If this wasn't you, secure your account: {url()}",
        f"ALERT: unusual sign-in detected on your {pick(SERVICES)} account. Reset here {url()}",
    ]
    return pick(t)

def spam_prize():
    t = [
        f"Congratulations! You've been selected to receive a FREE {pick(['iPhone 17', 'iPad', 'AirPods', '$500 gift card'])}. Claim your prize: {url()}",
        f"You have won {pick(AMOUNTS)} in our monthly draw! Claim your reward now {url()}",
        f"WINNER! Your number was chosen for a {pick(['$1,000', '$250'])} Walmart gift card. Claim here: {url()}",
    ]
    return pick(t)

def spam_loan():
    name = pick(FIRST_NAMES)
    t = [
        f"{name}, your {pick(AMOUNTS)} loan is pre-approved! Funds can be deposited today. Claim now: {url()}",
        f"Hi {name}! You qualify for a same-day cash advance up to {pick(['$5,000', '$2,500', '$1,000'])}. No credit check needed.",
        f"Bad credit OK! You are approved for a payday loan. Borrow up to {pick(['$1,000', '$2,000'])} instantly. {url()}",
        f"Final notice for {name}: your debt relief program enrollment expires today. Act now: {url()}",
        f"{name} your application was approved. {pick(AMOUNTS)} is ready for deposit. Accept funds: {url()}",
    ]
    return pick(t)

def spam_political():
    t = [
        f"It's official: {pick(POLS)} needs YOU. Chip in {pick(['$15', '$25', '$5'])} before {pick(DEADLINES)} and your gift is {pick(MATCHES)}! {url()}",
        f"{pick(POLS)} needs your answer! Take this approval poll and your donation will be {pick(MATCHES)}. Donate now.",
        f"URGENT: {pick(POLS)} is counting on patriots like you. Pitch in {pick(['$25', '$10'])} before {pick(DEADLINES)}!",
        f"Sign our petition to stop the radical agenda in Congress. Add your name now! {url()}",
        f"We're begging: {pick(POLS)} is about to lose this fight. Rush {pick(['$20', '$47'])} before {pick(DEADLINES)} - {pick(MATCHES)}",
    ]
    return pick(t)

def spam_pig_butchering():
    name = pick(FIRST_NAMES)
    t = [
        f"Hi, is this {name}?",
        f"Hey {name}, long time no see! How have you been?",
        f"Hello, are you {name}? It's me from the conference.",
        f"Sorry to bother you, is this {name}'s number?",
        f"Hi! It's been a while, remember me?",
    ]
    return pick(t)

def spam_crypto_job():
    t = [
        f"Earn {pick(['$500', '$300', '$800'])} per day trading bitcoin with our expert team! No experience needed. Join: {url()}",
        f"Hello! I'm a hiring manager. We offer flexible remote work, $300-800 per day. Contact me on WhatsApp to start.",
        f"Part-time work from home, {pick(['$200', '$450'])} daily, flexible hours, no experience. Reply YES to start",
        f"Your resume impressed us! Remote position, {pick(['$40', '$55'])}/hour. Message our recruiter on Telegram: @{pick(['hr_jobs', 'talent_team'])}",
    ]
    return pick(t)

SPAM_GENERATORS = [spam_delivery, spam_toll, spam_phishing, spam_prize,
                   spam_loan, spam_political, spam_pig_butchering, spam_crypto_job]

# --- Modern ham: conversational + legit transactional/OTP/marketing ---

def ham_conversation():
    t = [
        "Hey, are we still on for dinner tomorrow?",
        "Running 10 min late, sorry!",
        "Can you send me the address for Saturday?",
        "Thanks so much for yesterday. The kids had a blast.",
        "Your dad and I will land at 3pm. See you at baggage claim.",
        "Did you see the game last night?? unreal",
        "Grabbing coffee before the meeting, want anything?",
        "happy birthday!! hope it's a great one",
        "The plumber can come Thursday between 2-4, does that work?",
        "omw, be there in 15",
        "Don't forget the potluck is at 6 not 7",
        "Can you pick up milk on your way home?",
        f"Lunch at {pick(['noon', '12:30', '1'])}? I'm thinking tacos",
        "Movie starts at 8, meet at the entrance?",
        "That was so fun! let's do it again soon",
        "Just checking in, how did the interview go?",
        "I'll venmo you for my half tonight",
        "Snow day tomorrow, school's closed!",
    ]
    return pick(t)

def ham_transactional():
    t = [
        f"Your order number {random.randint(100000,999999)} has shipped. Track it in the app.",
        f"Reminder: your appointment with Dr. {pick(['Patel', 'Nguyen', 'Smith', 'Garcia'])} is scheduled for {pick(['Monday', 'Tuesday', 'Friday'])} at {pick(['2 PM', '10 AM', '3:30 PM'])}. Reply YES to confirm.",
        f"{pick(BANKS)}: Did you attempt a charge of ${random.randint(10,400)}.{random.randint(10,99)} at {pick(['SHELL', 'TARGET', 'COSTCO', 'AMAZON'])}? Reply YES or NO.",
        f"Your table for {random.randint(2,6)} at {pick(['Nopa', 'Che Fico', 'Zuni', 'Rich Table'])} is confirmed for {pick(['7:30 PM', '6 PM', '8 PM'])} tonight.",
        f"Your {pick(['Uber', 'Lyft'])} driver {pick(['Miguel', 'Sarah', 'Chen', 'Aisha'])} is arriving in a {pick(['white Camry', 'black Model 3', 'blue CR-V'])}.",
        f"Your prescription is ready for pickup at {pick(['Walgreens', 'CVS'])} on {pick(['Main St', 'Oak Ave'])}.",
        f"{pick(CARRIERS)}: Your package will arrive {pick(['Tuesday', 'tomorrow', 'today by 8pm'])}. Track: https://tools.usps.com/go/Track",
        f"Your {pick(['dentist', 'vision', 'annual physical'])} appointment is confirmed for {pick(['May 4', 'June 12', 'Sept 3'])} at {pick(['9 AM', '2 PM'])}.",
        f"{pick(BANKS)} alert: your statement is ready. Log in to your account to view it.",
        f"Your loan payment of ${random.randint(100,900)}.{random.randint(10,99)} was received. Thank you.",
    ]
    return pick(t)

def ham_otp():
    code = random.randint(1000, 999999)
    t = [
        f"Your verification code is {code}. Do not share this code.",
        f"G-{random.randint(100000,999999)} is your Google verification code.",
        f"Use code {code} to log in. It expires in 10 minutes.",
        f"Your {pick(SERVICES)} code is: {code}. Don't share it with anyone.",
        f"{code} is your {pick(['Instagram', 'TikTok', 'X', 'Snapchat'])} confirmation code",
        f"Your one-time passcode is {code}",
    ]
    return pick(t)

def ham_marketing():
    t = [
        f"{pick(['SEPHORA', 'GAP', 'OLD NAVY', 'TARGET'])}: {pick(['20%', '30%', '40%'])} off everything this weekend! Shop now. Reply STOP to opt out.",
        f"{pick(['Chipotle', 'Starbucks', 'Dominos'])}: Free delivery on orders ${random.randint(10,25)}+ today only. Reply STOP to end.",
        f"Your {pick(['CVS', 'Walgreens'])} ExtraBucks expire {pick(['Sunday', 'tomorrow'])}! Reply STOP to unsubscribe",
        f"{pick(['REI', 'Patagonia'])} members: the {pick(['spring', 'holiday'])} sale starts Friday. Details in app. Txt STOP to opt out",
    ]
    return pick(t)

HAM_GENERATORS = [
    (ham_conversation, 8),
    (ham_transactional, 6),
    (ham_otp, 4),
    (ham_marketing, 2),
]

def main(n_spam=1500, n_ham=1500, out="modern_corpus.csv"):
    rows = []
    for i in range(n_spam):
        gen = SPAM_GENERATORS[i % len(SPAM_GENERATORS)]
        rows.append(("spam", gen()))
    weighted = list(itertools.chain.from_iterable([[g] * w for g, w in HAM_GENERATORS]))
    for i in range(n_ham):
        rows.append(("ham", pick(weighted)()))
    random.shuffle(rows)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "text"])
        w.writerows(rows)
    from collections import Counter
    print(Counter(r[0] for r in rows), "->", out)

if __name__ == "__main__":
    main()
