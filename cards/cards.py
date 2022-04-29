import random

def init_deck():
    deck = []
    for suit in ["Spades", "Hearts", "Diamonds", "Clubs"]:
        for rank in ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"]:
            deck.append((rank, suit))
    return deck

def init_hand(deck):
    hand = []
    for i in range(2):
        draw_card(deck, hand)
    return hand

def draw_card(deck, hand):
    num = random.randint(0, len(deck)-1)
    hand.append(deck.pop(num))

def get_points(hand):
    points = 0
    for card in hand:
        rank = card[0]
        if rank == "A":
            points += 1
        elif rank in ["J", "Q", "K", "10"]:
            points += 0
        else:
            points += int(rank)

    if points > 9:
        points = points - 10
    return points

def pretty_print(hand):
    result = []
    for card in hand:
        result.append(convert(card))
    return result

def convert(card):
    return card[0] + " " + card[1]

# game loop
money = 100

while True:
    deck = init_deck()
    handA = init_hand(deck)
    handB = init_hand(deck)
    hand = input("Choose either Player A or Player B to win: ")

    print("Player A cards:", pretty_print(handA))
    pointsA = get_points(handA)
    print("Initial hand value:", pointsA)
    if  pointsA != 8 and pointsA != 9:
        draw_card(deck, handA)
        print("Player A draws a", convert(handA[-1]))
        pointsA = get_points(handA)
    print("Player A is done\nPlayer A final total is:", pointsA)

    print("Player B cards:", pretty_print(handB))
    pointsB = get_points(handB)
    print("Initial hand value:", pointsB)
    if  pointsB != 8 and pointsB != 9:
        draw_card(deck, handB)
        print("Player B draws a", convert(handB[-1]))
        pointsB = get_points(handB)
    print("Player B is done\nPlayer B final total is:", pointsB)

    if pointsA > pointsB:
        print("Player A wins")
        if hand == "A" or hand == "a":
            print("You win")
            money += 10
        else:
            print("You lost")
            money -= 10
    elif pointsA < pointsB:
        print("Player B wins")
        if hand == "B" or hand == "b":
            print("You win")
            money += 10
        else:
            print("You lost")
            money -= 10
    else:
        print("It's a tie\nNO winner")

    print("money is:", money)
    print()

    if money <= 0:
        print("You have no money!")
        break

    if money >= 200:
        print("You are rich!")
        break
