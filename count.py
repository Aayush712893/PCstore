# Write code here
start = int(input("Enter the number from which counting should be started = "))
end = int(input("Enter the number from which counting should be ended = "))
digit_to_be_counted = int(input("Enter the digit that needs to be counted between the start number and end number = "))
count = 0
for num in range(start, end + 1):
  temp = num
  while temp > 0:
    last_digit = temp % 10
    if last_digit == digit_to_be_counted:
      count += 1
    temp //= 10
print(f"The digit {digit_to_be_counted} appears {count} times between {start} to {end}")