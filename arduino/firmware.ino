/* Copyrigth (C) 1014 Sampsa Vierros
 * Licence: GNU GPL v2
*/

const int redInPin = 2;
const int redOutPin = 3;
const int whiteInPin = 4;
const int whiteOutPin = 5;
const int switchDelay = 1; 
const int byteDelay = 0;

void setup() {
  Serial.begin(115200);
  pinMode(redOutPin, OUTPUT);
  pinMode(whiteOutPin, OUTPUT);
  pinMode(redInPin, INPUT);
  pinMode(whiteInPin, INPUT);
}

void sendBit(byte state) {
  if(state == 0) {
    // Send zero bit
    digitalWrite(redOutPin, HIGH);  // Set red to zero by making transistor to conduct
    delay(switchDelay);
    while(digitalRead(whiteInPin) != LOW) {
      // Wait until receiver acknowledges by setting white to low
      ;
    }
    delay(switchDelay);
    digitalWrite(redOutPin, LOW); // Set red to high
    delay(switchDelay);
    while(digitalRead(whiteInPin) != HIGH) {
      // Wait until receiver acknowledges by setting white to high
      ;
    }
  } else if(state == 1) {
    // Send one bit
    digitalWrite(whiteOutPin, HIGH);  // Set white to zero
    delay(switchDelay);
    while(digitalRead(redInPin) != LOW) {
      // Wait until sender acknowledges by setting red to low
      ;
    }
    delay(switchDelay);
    digitalWrite(whiteOutPin, LOW); // Set red to high
    delay(switchDelay);
    while(digitalRead(redInPin) != HIGH) {
      // Wait until receiver acknowledges by setting red to high
      ;
    }
  }
}

byte receiveBit() {
  delay(switchDelay);
  byte white = digitalRead(whiteInPin);
  byte red = digitalRead(redInPin);
  if((red == LOW) && (white == HIGH)) {
    // Receiving zero bit
    digitalWrite(whiteOutPin, HIGH);  // Acknowledge by setting white to zero
    delay(switchDelay);
    while(digitalRead(redInPin) != HIGH) {
      // Wait until sender acknowledges by setting red to high
      ;
    }
    delay(switchDelay);
    digitalWrite(whiteOutPin, LOW);
    return 0;
  } else if((white == LOW) && (red == HIGH)) {
    // Receiving one bit
    digitalWrite(redOutPin, HIGH);  // Acknowledge by setting red to zero
    delay(switchDelay);
    while(digitalRead(whiteInPin) != HIGH) {
      // Wait until sender acknowledges by setting white to high
      ;
    }
    delay(switchDelay);
    digitalWrite(redOutPin, LOW);
    return 1;
  }
}

byte receiveByte() {
  byte data = 0;
  byte tmp = 0;
  for(byte i=0; i<8; i++) {
    tmp = receiveBit();
    data = data | (tmp << i);
  }
  delay(byteDelay);
  //Serial.println(data);
  return data;
}

void sendByte(byte data) {
  byte state = 0; 
  for(byte i=0; i<8; i++) {
    state = (data >> i) & 1;  // LSb first
    sendBit(state);
  }
  delay(byteDelay);
}

void sendToCalc() {
  while(Serial.available() > 0) {
    sendByte(Serial.read());
  }
}

void sendToHost() {
  byte data;
  data = receiveByte();
  Serial.write(data);
}

void sendPinState() {
  byte white = digitalRead(whiteInPin);
  byte red = digitalRead(redInPin);
  Serial.write("White: ");
  if(white == LOW) 
    Serial.write("LOW\n");
  else
    Serial.write("HIGH\n");
  Serial.write("Red: ");
  if(red == LOW) 
    Serial.write("LOW\n");
  else
    Serial.write("HIGH\n");
}

void loop() {
  // See if calculator wants to send something
  byte white = digitalRead(whiteInPin);
  byte red = digitalRead(redInPin);
  if((white == LOW) || (red == LOW)) {
    sendToHost();
  }
  
  
  // See if host wants to send something
  if(Serial.available() > 0) {
    sendToCalc();
  }
  
}
