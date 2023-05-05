package config

import (
	"io"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

type Color struct {
	Username  string `yaml:"username"`
	EventType string `yaml:"eventtype"`
	EventTime string `yaml:"eventtime"`
	SourceIP  string `yaml:"sourceip"`
	StartTime string `yaml:"starttime"`
	EndTime   string `yaml:"endtime"`
	Port      string `yaml:"port"`
}

type Config struct {
	AuthKeys     string `yaml:"authkeys"`
	Bucket       string `yaml:"bucket"`
	OutputFormat string `yaml:"output"`
	LogFile      string `yaml:"log"`
	Database     string `yaml:"database"`
	ColorFlag    bool   `yaml:"color_flag"`
	Color        Color  `yaml:"color"`
}

var Conf Config

func LoadConfig(configFile string) {
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Error opening config file: %v", err)
	}
	defer file.Close()

	byteValue, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	err = yaml.Unmarshal(byteValue, &Conf)
	if err != nil {
		log.Fatalf("Error unmarshalling config file: %v", err)
	}
}
