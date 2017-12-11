//
//  InterfaceController.m
//  hello_watch_os WatchKit Extension
//
//  Created by Ian Beer on 10/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "InterfaceController.h"

#include <stdio.h>
#include "spawner.h"

@interface InterfaceController ()

@end


@implementation InterfaceController

- (void)awakeWithContext:(id)context {
    [super awakeWithContext:context];

    // Configure interface objects here.
}

- (void)willActivate {
    // This method is called when watch view controller is about to be visible to user
    [super willActivate];
}

- (void)didDeactivate {
    // This method is called when watch view controller is no longer visible
    [super didDeactivate];
}
- (IBAction)run_poc {
  printf("hello from clicking the go button!\n");
  go();
}

@end



