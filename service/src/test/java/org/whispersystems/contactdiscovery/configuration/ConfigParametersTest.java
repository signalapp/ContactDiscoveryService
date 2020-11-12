package org.whispersystems.contactdiscovery.configuration;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ConfigParametersTest {

  public static final String CONFIG_STRING_VALUE   = "config-string";
  public static final String PROPERTY_STRING_KEY   = "test.string";
  public static final String PROPERTY_STRING_VALUE = "property-string-value";

  public static final Integer CONFIG_INTEGER_VALUE   = 1000;
  public static final String  PROPERTY_INTEGER_KEY   = "test.integer";
  public static final Integer PROPERTY_INTEGER_VALUE = 2000;


  @Before
  public void clearState() {
    System.clearProperty(PROPERTY_STRING_KEY);
    System.clearProperty(PROPERTY_INTEGER_KEY);
  }

  @Test
  public void testStringValues() {
    // with no default set and no property set, we should get nothing back.
    assertTrue(ConfigParameters.getString(PROPERTY_STRING_KEY).isEmpty());

    // with default set and no property set, we should get the default value back.
    assertEquals(CONFIG_STRING_VALUE, ConfigParameters.getString(PROPERTY_STRING_KEY).orElse(CONFIG_STRING_VALUE));

    System.setProperty(PROPERTY_STRING_KEY, PROPERTY_STRING_VALUE);
    // with default and property set, we should get the property value back.
    assertEquals(PROPERTY_STRING_VALUE, ConfigParameters.getString(PROPERTY_STRING_KEY).orElse(CONFIG_STRING_VALUE));
  }

  @Test
  public void testIntegerValues() {
    // with no default set and no property set, we should get nothing back.
    assertTrue(ConfigParameters.getInteger(PROPERTY_INTEGER_KEY).isEmpty());

    // with default set and no property set, we should get the default value back.
    assertEquals(CONFIG_INTEGER_VALUE, ConfigParameters.getInteger(PROPERTY_INTEGER_KEY).orElse(CONFIG_INTEGER_VALUE));

    System.setProperty(PROPERTY_INTEGER_KEY, PROPERTY_INTEGER_VALUE.toString());
    // with default and property set, we should get the property value back.
    assertEquals(PROPERTY_INTEGER_VALUE, ConfigParameters.getInteger(PROPERTY_INTEGER_KEY).orElse(CONFIG_INTEGER_VALUE));
  }
}