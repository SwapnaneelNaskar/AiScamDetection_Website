"""
Training and benchmark dataset for AI Scam Detector.
Covers real-world scam patterns across 7 major threat categories
as well as authentic legitimate messages (SMS, Email, Chat, Alerts).
"""

DATASET = [
    # ==========================================
    # PRIZE / LOTTERY SCAMS
    # ==========================================
    {
        "text": "Congratulations! You have won Rs 25,00,000 in the National Lucky Draw. Pay Rs 999 processing fee immediately to claim your prize. Click: http://claim-prize-example.xyz",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "Dear Winner, your mobile number has won $1,000,000 in the Coca Cola International Lottery. Send your bank details and $150 transfer tax to claim.",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "You are the lucky selected customer of the year! Claim your free iPhone 15 Pro Max today. Click http://free-reward-gift.top/claim before time runs out.",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "BIG WIN! Your ticket matched 6 numbers. Win Rs 50 Lakhs cash prize! Call 9876543210 or visit bit.ly/prize-claim-now to complete your claim registration.",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "Notice: You received a Rs 5000 Amazon Gift Voucher. Redeem immediately within 24 hours at http://amazon-rewards-claim.xyz/gift or offer will expire.",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "Dear Customer, Flipkart anniversary lucky spin won you a Brand New Honda City! Transfer Rs 4,999 registration fee to R.T.O account immediately.",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "Jackpot alert! You have qualified for Rs 10 Lakh cash reward from Kaun Banega Crorepati. Contact lottery manager Rana Pratap on WhatsApp +917890123456.",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "Congratulations! You have an unclaimed cashback of Rs 3,450 waiting in your Google Pay account. Click here http://gpay-cashback-reward.xyz/receive to redeem.",
        "category": "Prize Scam",
        "is_scam": 1
    },
    {
        "text": "Hurry! You have been awarded 10,000 loyalty points worth Rs 10,000. Redeem cash directly to your bank account at http://loyalty-cash-redeem.cc/login.",
        "category": "Prize Scam",
        "is_scam": 1
    },

    # ==========================================
    # PHISHING / CREDENTIAL THEFT
    # ==========================================
    {
        "text": "URGENT! Your SBI account has been suspended due to incomplete KYC. Update your PAN and Aadhaar immediately at http://sbi-kyc-verify-portal.xyz to avoid permanent blockage.",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "Dear HDFC customer, your NetBanking access is disabled. Please verify your identity and enter password at http://hdfc-netbanking-secure.top/login immediately.",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "Security Alert: Unusual sign-in detected on your Microsoft 365 account from Moscow, Russia. If this was not you, verify your login credentials here: http://ms-security-check.icu",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "Your Netflix membership renewal payment failed. To avoid cancellation of your streaming subscription, update your credit card details now: http://netflix-billing-update.cc",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "PayPal Alert: We noticed unauthorized activity on your account. Log in immediately to verify your transaction history: http://192.168.1.105/paypal/secure-login",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "ICICI Bank Warning: Your debit card will be blocked within 12 hours. Click http://icici-card-update.top to update your mobile number and card PIN.",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "Apple Support: Your iCloud account is locked due to multiple wrong password attempts. Unlock your Apple ID at http://appleid-verification-icloud.xyz/verify",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "Google Security: Unauthorized access detected from Chrome OS in Vietnam. Verify your Google Workspace credentials now at http://accounts-google-verify.site/signin",
        "category": "Phishing",
        "is_scam": 1
    },
    {
        "text": "Income Tax Alert: Tax refund of Rs 15,490 approved. Submit your bank account number and NetBanking password at http://incometax-refund-gov.xyz/login to receive refund.",
        "category": "Phishing",
        "is_scam": 1
    },

    # ==========================================
    # DELIVERY / PARCEL SCAMS
    # ==========================================
    {
        "text": "FedEx: Your package #FD-8921 is held at customs due to an incomplete delivery address. Pay Rs 85 redelivery fee to dispatch today: http://fedx-deliver-status.xyz/pay",
        "category": "Delivery Scam",
        "is_scam": 1
    },
    {
        "text": "India Post: Your parcel has arrived at the sorting center but cannot be delivered due to missing house number. Please update your address within 24 hours at http://indiapost-parcel-update.top",
        "category": "Delivery Scam",
        "is_scam": 1
    },
    {
        "text": "DHL Express: Delivery failure for shipment DHL-992147. A rescheduling charge of $2.99 is required. Update your payment details at http://dhl-shipment-redelivery.buzz",
        "category": "Delivery Scam",
        "is_scam": 1
    },
    {
        "text": "BlueDart Alert: Your consignment is detained at terminal. Pay outstanding clearance tax of Rs 250 immediately to avoid return to sender: http://bluedart-trace.icu",
        "category": "Delivery Scam",
        "is_scam": 1
    },
    {
        "text": "Amazon Courier: We attempted to deliver your package today but no one was home. Reschedule your delivery and confirm address: http://amz-courier-track.work/reschedule",
        "category": "Delivery Scam",
        "is_scam": 1
    },
    {
        "text": "UPS Notification: Your package delivery has been suspended. Additional import duties of $3.50 must be settled before release: http://ups-import-fees.top",
        "category": "Delivery Scam",
        "is_scam": 1
    },

    # ==========================================
    # JOB / WORK-FROM-HOME SCAMS
    # ==========================================
    {
        "text": "Part-time job opportunity! Earn Rs 3,000 to Rs 8,000 daily from home by liking YouTube videos and rating hotels on Google Maps. No experience needed. Contact HR manager on Telegram @EarnDailyJobs.",
        "category": "Job Scam",
        "is_scam": 1
    },
    {
        "text": "Urgent hiring: Amazon Part-Time Data Entry Operator. Work 1 hour per day and make Rs 50,000 monthly. Deposit Rs 1,500 security deposit for training software. WhatsApp us now.",
        "category": "Job Scam",
        "is_scam": 1
    },
    {
        "text": "Congratulations! Your resume has been shortlisted for Google Remote Assistant. Salary $45/hour. Pay $99 equipment verification fee to receive laptop.",
        "category": "Job Scam",
        "is_scam": 1
    },
    {
        "text": "Earn money online with Crypto Trading tasks! Invest Rs 1,000 and get Rs 3,000 return in 20 minutes guaranteed. Join our VIP Telegram channel bit.ly/crypto-wealth-fast",
        "category": "Job Scam",
        "is_scam": 1
    },
    {
        "text": "Tata Consultancy Services recruitment: You are selected for Junior Software Engineer. Offer letter ready. Pay Rs 2,500 medical examination fee to claim appointment letter.",
        "category": "Job Scam",
        "is_scam": 1
    },
    {
        "text": "Work from home reviewing movie trailers! Earn Rs 500 per movie reviewed. Daily payout via UPI. Register today at http://wfh-movie-review-jobs.xyz",
        "category": "Job Scam",
        "is_scam": 1
    },

    # ==========================================
    # FINANCIAL SCAMS & EXTORTION
    # ==========================================
    {
        "text": "Dear customer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Immediately call electricity officer at 9812345678.",
        "category": "Financial Scam",
        "is_scam": 1
    },
    {
        "text": "Urgent Loan Approval! Pre-approved personal loan of Rs 5,00,000 with 0% interest for 1 year. Pay Rs 2,999 file processing fee to disburse amount within 10 minutes.",
        "category": "Financial Scam",
        "is_scam": 1
    },
    {
        "text": "Attention: Income tax raid scheduled at your premises for undeclared wealth. Transfer Rs 50,000 to government settlement officer to clear all criminal charges.",
        "category": "Financial Scam",
        "is_scam": 1
    },
    {
        "text": "Double your Bitcoin in 24 hours! Guaranteed 200% return on Ethereum and BTC investments. Send your crypto to our smart contract wallet: 0x71C... and watch it multiply.",
        "category": "Financial Scam",
        "is_scam": 1
    },
    {
        "text": "Police Department: Your digital arrest warrant has been issued under Section 420. Stay on call and transfer all bank funds to RBI safety verification account immediately.",
        "category": "Financial Scam",
        "is_scam": 1
    },
    {
        "text": "Your mutual fund portfolio has a pending dividend payout of Rs 42,000. Pay Rs 500 stamp duty fee at http://mutual-dividend-claim.top to transfer funds to your UPI.",
        "category": "Financial Scam",
        "is_scam": 1
    },

    # ==========================================
    # ACCOUNT TAKEOVER & IMPERSONATION
    # ==========================================
    {
        "text": "WhatsApp Support: Your account will be deleted within 24 hours due to violation of terms. Send the 6-digit verification code you received to confirm your identity.",
        "category": "Account Takeover",
        "is_scam": 1
    },
    {
        "text": "Bank Manager Sharma from SBI: We are updating your ATM chip card. Kindly provide the OTP received on your mobile to activate free lifetime insurance.",
        "category": "Account Takeover",
        "is_scam": 1
    },
    {
        "text": "Instagram Security: We received a copyright infringement complaint against your profile. Verify your account ownership or your account will be deleted: http://ig-copyright-appeal.xyz",
        "category": "Account Takeover",
        "is_scam": 1
    },
    {
        "text": "Telegram Security: Someone requested your account deletion. If you did not make this request, send the login code received via SMS to cancel deletion.",
        "category": "Account Takeover",
        "is_scam": 1
    },
    {
        "text": "Hello Mom, my phone broke and I am messaging from a friend's phone. I urgently need Rs 15,000 for emergency hospital deposit. Please transfer to this UPI ID right now.",
        "category": "Impersonation",
        "is_scam": 1
    },
    {
        "text": "Hi, I am Captain Mark from US Army deployed overseas. I need to transfer $5 million gold consignment to your home. Pay $2,000 customs clearance at port.",
        "category": "Impersonation",
        "is_scam": 1
    },
    {
        "text": "Airtel Customer Service: Your 4G SIM will be deactivated today due to 5G network migration. Dial *121*55*<fraud_code># to keep your SIM active.",
        "category": "Impersonation",
        "is_scam": 1
    },

    # ==========================================
    # LEGITIMATE / SAFE MESSAGES
    # ==========================================
    {
        "text": "Dear Customer, Rs 1,500.00 debited from your A/c XX4892 on 24-Sep-24 towards Amazon Retail. Available balance: Rs 42,310.50. Call 1800112211 if not done by you. - SBI",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Your OTP for login to HDFC NetBanking is 591823. Valid for 10 minutes. Do not share your OTP, NetBanking password, or CVV with anyone including bank staff.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Hi Rahul, are we still meeting for the project discussion today at 4 PM in the college cafeteria? Let me know once you reach.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Swiggy: Your order from Biryani Blues is out for delivery! Track your delivery partner Suresh on the Swiggy mobile application. Estimated arrival: 18 mins.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Indigo Airlines: Web check-in for flight 6E-2415 Delhi to Bengaluru is now open. Visit https://www.goindigo.in or use the IndiGo mobile app to select your seat.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Dear user, your electricity bill for consumer no. 10293847 is Rs 1,420. Due date is 30-Sep-2024. Pay online through official portal https://www.tatapower.com",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Your Flipkart order with item 'Noise Wireless Earbuds' has been shipped via Ekart. Track your order on the Flipkart official app.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Reminder: Your appointment with Dr. Mehta at Apollo Hospital is scheduled for tomorrow at 11:30 AM. Please arrive 15 minutes prior.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Google verification code: 829471. Use this code to verify your phone number. Google will never ask you for this code.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Hey, did you review the lab assignment files sent by the professor yesterday? Need help with problem 3.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Uber: Your ride with driver Ramesh (Swift Dzire DL01AB1234) is arriving in 3 mins. Share your pin 7412 when boarding.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Netflix: A new device signed in to your account from Chrome on Windows in New Delhi. If this was you, you can ignore this email.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Your mobile recharge for Airtel number 9876543210 of Rs 299 was successful. 1.5GB/day + Unlimited Calls for 28 days activated.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "IRCTC: PNR 245-1234567 Train 12952 Mumbai Rajdhani. Class 3A Coach B4 Berth 23 (Confirmed). Chart not prepared yet.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Good morning team, the weekly CSE department seminar will be held this Thursday at 10 AM in Auditorium Hall B. Attendance is mandatory.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "GitHub: A personal access token for your repository has expired. Visit https://github.com/settings/tokens to generate a new token.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Dear employee, your monthly salary slip for August 2024 has been generated and uploaded to the company HR portal.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "BookMyShow: Booking confirmed for Stree 2 at PVR Cinema, Audi 4, Seats F12, F13. Show time: Today 8:15 PM.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "Zomato Gold: Get 40% flat off at your favorite dining restaurants this weekend. Open the Zomato app to check participating venues.",
        "category": "Legitimate",
        "is_scam": 0
    },
    {
        "text": "State Bank of India: Your loan account interest certificate for FY 2023-24 has been dispatched to your registered email address.",
        "category": "Legitimate",
        "is_scam": 0
    }
]

# Function to augment dataset with common variations to produce a robust training corpus
def get_augmented_dataset():
    augmented = list(DATASET)
    
    # Variations of prize messages
    prize_templates = [
        ("Lucky winner! Claim cash reward of Rs {amount}. Pay Rs {fee} verification fee: http://prize-{rnd}.xyz", "Prize Scam", 1),
        ("Congratulations! You won free coupon of Rs {amount} on Amazon. Click http://claim-voucher-{rnd}.top", "Prize Scam", 1),
        ("Dear user, you have won iPhone 15 in Mega Lucky Draw! Transfer Rs {fee} dispatch fee immediately to claim.", "Prize Scam", 1),
        ("KBC Lucky Winner of Rs {amount}! Send your Aadhaar and bank details to manager WhatsApp: +919988776655", "Prize Scam", 1),
        ("Cashback reward of Rs {amount} is pending approval. Claim to your Paytm/UPI now at http://cashback-offer-{rnd}.buzz", "Prize Scam", 1),
    ]
    
    # Variations of phishing messages
    phishing_templates = [
        ("URGENT: Your {bank} account will be blocked within 24 hours. Update KYC documents immediately: http://{bank_slug}-kyc-update-{rnd}.xyz", "Phishing", 1),
        ("Security Notice: Unauthorized login to your {bank} NetBanking. Verify your password now at http://{bank_slug}-security-{rnd}.top", "Phishing", 1),
        ("Important: Income Tax Department detected tax fraud. Pay penalty or update details at http://incometax-verify-{rnd}.icu", "Phishing", 1),
        ("Your credit card reward points worth Rs {amount} will expire tonight! Redeem directly into cash at http://points-redeem-{rnd}.cc", "Phishing", 1),
        ("Dear customer, your PAN card is not linked to your {bank} account. Click http://pan-link-{rnd}.work to link now.", "Phishing", 1),
    ]

    # Variations of delivery messages
    delivery_templates = [
        ("{courier} Notification: Your package delivery was unsuccessful due to wrong address. Reschedule at http://{courier_slug}-delivery-{rnd}.xyz", "Delivery Scam", 1),
        ("Package on hold! Pay Rs {fee} customs clearance fee to release parcel {courier}-9982: http://clearance-{courier_slug}-{rnd}.top", "Delivery Scam", 1),
        ("{courier} Express: Address incomplete for shipment #88124. Confirm street address within 12 hours: http://{courier_slug}-track-{rnd}.icu", "Delivery Scam", 1),
    ]

    # Variations of job scams
    job_templates = [
        ("Online part-time job! Earn Rs {amount} daily by typing captcha and watching videos. Register on Telegram @JobHelper{rnd}", "Job Scam", 1),
        ("Urgent opening: Remote Rating Assistant. Earn Rs {amount} per week. Deposit Rs {fee} registration fee to start immediately.", "Job Scam", 1),
        ("Hiring for YouTube like job. Rs 50 per like, earn Rs 3000 daily from home. Join Telegram t.me/youtube_tasks_{rnd}", "Job Scam", 1),
    ]

    # Variations of financial scams
    financial_templates = [
        ("Electricity disconnection alert! Your power supply will be cut off tonight at 9:30 PM. Pay outstanding bill to officer: 98112233{rnd}", "Financial Scam", 1),
        ("Approved! Instant personal loan of Rs {amount} at 1% interest. Pay processing charge Rs {fee} to disburse money within 5 mins.", "Financial Scam", 1),
        ("Double your savings in 3 days with AI trading algorithms. Deposit Rs {amount} and withdraw 3x returns guaranteed.", "Financial Scam", 1),
    ]

    # Variations of legitimate messages
    legit_templates = [
        ("Dear Customer, Rs {amount} credited to your account XX{rnd} on {date}. Total available balance is Rs 56,120. - SBI", "Legitimate", 0),
        ("Your one time password (OTP) is {rnd}{fee}. Valid for 5 minutes. Do not share OTP with anyone. - HDFC Bank", "Legitimate", 0),
        ("Your order #{rnd} has been confirmed and will be delivered by tomorrow. Track details on our official mobile app.", "Legitimate", 0),
        ("Your flight booking 6E-{rnd} from Mumbai to Delhi is confirmed for {date}. Web check-in opens 48 hours prior.", "Legitimate", 0),
        ("Hi, please find attached the meeting minutes and agenda for our software engineering project sprint.", "Legitimate", 0),
        ("Electricity bill for consumer #{rnd} for amount Rs {amount} has been paid successfully via UPI. Transaction ID: TXN{rnd}.", "Legitimate", 0),
        ("Reminder: Your doctor appointment with Dr. Sharma is scheduled for {date} at 5:00 PM. Please carry your previous reports.", "Legitimate", 0),
        ("Security Code: {rnd}{fee}. If you did not request this code, change your account password immediately.", "Legitimate", 0),
        ("Hey, did you complete the homework for machine learning class? Let's review before tomorrow's lecture.", "Legitimate", 0),
        ("Your subscription has been renewed successfully. Next billing date is {date}. Thank you for using our service.", "Legitimate", 0)
    ]

    banks = [("SBI", "sbi"), ("HDFC", "hdfc"), ("ICICI", "icici"), ("Axis Bank", "axis"), ("Kotak", "kotak"), ("PNB", "pnb")]
    couriers = [("FedEx", "fedex"), ("DHL", "dhl"), ("IndiaPost", "indiapost"), ("BlueDart", "bluedart"), ("UPS", "ups")]
    amounts = ["10,000", "25,000", "50,000", "1,00,000", "5,00,000", "25,00,000"]
    fees = ["49", "99", "199", "499", "999", "1,499"]

    import random
    rng = random.Random(42)  # deterministic seed

    for i in range(30):
        # Prize
        tmpl, cat, label = rng.choice(prize_templates)
        augmented.append({
            "text": tmpl.format(amount=rng.choice(amounts), fee=rng.choice(fees), rnd=rng.randint(100, 999)),
            "category": cat,
            "is_scam": label
        })
        # Phishing
        tmpl, cat, label = rng.choice(phishing_templates)
        b_name, b_slug = rng.choice(banks)
        augmented.append({
            "text": tmpl.format(bank=b_name, bank_slug=b_slug, amount=rng.choice(amounts), rnd=rng.randint(100, 999)),
            "category": cat,
            "is_scam": label
        })
        # Delivery
        tmpl, cat, label = rng.choice(delivery_templates)
        c_name, c_slug = rng.choice(couriers)
        augmented.append({
            "text": tmpl.format(courier=c_name, courier_slug=c_slug, fee=rng.choice(fees), rnd=rng.randint(100, 999)),
            "category": cat,
            "is_scam": label
        })
        # Job
        tmpl, cat, label = rng.choice(job_templates)
        augmented.append({
            "text": tmpl.format(amount=rng.choice(amounts), fee=rng.choice(fees), rnd=rng.randint(100, 999)),
            "category": cat,
            "is_scam": label
        })
        # Financial
        tmpl, cat, label = rng.choice(financial_templates)
        augmented.append({
            "text": tmpl.format(amount=rng.choice(amounts), fee=rng.choice(fees), rnd=rng.randint(100, 999)),
            "category": cat,
            "is_scam": label
        })
        # Legitimate (add 2 to balance)
        for _ in range(3):
            tmpl, cat, label = rng.choice(legit_templates)
            augmented.append({
                "text": tmpl.format(
                    amount=rng.choice(amounts),
                    fee=rng.choice(fees),
                    rnd=rng.randint(1000, 9999),
                    date=f"{rng.randint(1, 28)}-Oct-2024"
                ),
                "category": cat,
                "is_scam": label
            })

    return augmented
