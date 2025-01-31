package database

import (
	"go.mongodb.org/mongo-driver/v2/mongo"
	"gorm.io/gorm"
)

var DB *gorm.DB

var MongoDB *mongo.Collection
